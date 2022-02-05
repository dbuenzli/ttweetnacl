(*---------------------------------------------------------------------------
   Copyright (c) 2022 The ttweetnacl programmers. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

let strf = Printf.sprintf

(* Hex *)

let lower_hex_digit n =
  let n = n land 0xF in Char.unsafe_chr (if n < 10 then 0x30 + n else 0x57 + n)

let is_hex_digit = function
| '0' .. '9' | 'A' .. 'F' | 'a' .. 'f' -> true | _ -> false

let hex_digit_value = function
| '0' .. '9' as c -> Char.code c - 0x30
| 'A' .. 'F' as c -> 10 + (Char.code c - 0x41)
| 'a' .. 'f' as c -> 10 + (Char.code c - 0x61)
| c -> invalid_arg (strf  "%C: not a hex digit" c)

type hex_error = Odd_hex_digits | Illegal_char of Char.t * int
let hex_error_message = function
| Odd_hex_digits -> "Odd number of hexadecimal digits"
| Illegal_char (c, i) -> strf "Illegal character %C at index %d" c i

let hex_is_valid s =
  let rec loop s max i hcount = match i > max with
  | true -> if hcount mod 2 <> 0 then Error Odd_hex_digits else Ok (hcount / 2)
  | false ->
      match s.[i] with
      | '0' .. '9' | 'A' .. 'F' | 'a' .. 'f' -> loop s max (i + 1) (hcount + 1)
      | ' ' | '-' -> loop s max (i + 1) hcount
      | c -> Error (Illegal_char (c, i))
  in
  loop s (String.length s - 1) 0 0

(* Bytes *)

type bigbytes =
  (int, Bigarray.int8_unsigned_elt, Bigarray.c_layout)
    Stdlib.Bigarray.Array1.t

let err_length ~exp ~fnd =
  "Bytes length, expected " ^ string_of_int exp ^ " found " ^ string_of_int fnd

let pp_labelled_bytes pp_bytes label ppf b =
  Format.fprintf ppf "@[%s: @[%a@]@]" label pp_bytes b

module type BYTES = sig
  type t
  val create : int -> init:int -> t
  val init : int -> init:(int -> int) -> t
  val length : t -> int
  val get : t -> int -> int
  val set : t -> int -> int -> unit
  val copy : t -> t
  val clear : t -> unit
  val blit : src:t -> int -> dst:t -> int -> len:int -> unit
  val of_string : string -> t
  val to_string : t -> string
  val of_bytes : bytes -> t
  val to_bytes : t -> bytes
  val of_bigbytes : bigbytes -> t
  val to_bigbytes : t -> bigbytes
  type hex_error = Odd_hex_digits | Illegal_char of Char.t * int
  val hex_error_message : hex_error -> string
  val of_hex : string -> (t, hex_error) result
  val of_hex' : string -> (t, string) result
  val to_hex : ?sep:char -> t -> string
  val pp : Format.formatter -> t -> unit
end

module Bytes_bigbytes = struct
  type t =
    (int,Bigarray.int8_unsigned_elt,Bigarray.c_layout) Bigarray.Array1.t

  let _create n = Bigarray.(Array1.create int8_unsigned c_layout n)
  let create n ~init:v = let a = _create n in Bigarray.Array1.fill a v; a
  let init n ~init = Bigarray.(Array1.init int8_unsigned c_layout n init)
  let[@inline] length b = Bigarray.Array1.dim b
  let[@inline] get b i = (Bigarray.Array1.get : t -> int -> int) b i
  let[@inline] get_char b i = Char.chr (get b i)
  let[@inline] set b i v = (Bigarray.Array1.set : t -> int -> int -> unit) b i v
  let copy b = let b' = _create (length b) in Bigarray.Array1.blit b b'; b'
  let clear b = Bigarray.Array1.fill b 0
  let blit ~src i ~dst k ~len =
    let src = Bigarray.Array1.sub src i len in
    let dst = Bigarray.Array1.sub dst k len in
    Bigarray.Array1.blit src dst

  let[@inline] check_length b len =
    let fnd = length b in
    if fnd <> len then raise (Invalid_argument (err_length ~exp:len ~fnd))

  (* XXX could use a bit of memcpy here. *)
  let of_string s = init (String.length s) ~init:(String.get_uint8 s)
  let to_string b = String.init (length b) (get_char b)
  let of_bytes b = init (Bytes.length b) ~init:(Bytes.get_uint8 b)
  let to_bytes b = Bytes.init (length b) (get_char b)
  let of_bigbytes b = init (length b) ~init:(get b)
  let to_bigbytes = of_bigbytes

  type nonrec hex_error = hex_error =
    | Odd_hex_digits | Illegal_char of Char.t * int

  let hex_error_message = hex_error_message
  let of_hex s = match hex_is_valid s with
  | Error _ as e -> e
  | Ok len ->
      let b = _create len in
      let rec find_hex_digit s k = match s.[k] with
      | '0' .. '9' | 'A' .. 'F' | 'a' .. 'f' -> k
      | _ -> find_hex_digit s (k + 1)
      in
      let rec loop b i max s k = match i > max with
      | true -> Ok b
      | false ->
          let k = find_hex_digit s k in
          let hi = hex_digit_value s.[k] in
          let k = find_hex_digit s (k + 1) in
          let lo = hex_digit_value s.[k] in
          set b i ((hi lsl 4) lor lo);
          loop b (i + 1) max s (k + 1)
      in
      loop b 0 (len - 1) s 0

  let of_hex' s = Result.map_error hex_error_message (of_hex s)
  let to_hex ?sep b =
    let blen = length b in
    let slen, sep = match sep with None -> 0, '\x00' | Some sep -> 1, sep in
    let s = Bytes.create (blen * 2 + (blen - 1) * slen) in
    let max = blen - 1 and i = ref 0 and k = ref 0 in
    while (!i <= max) do
      let byte = get b !i in
      Bytes.set s !k (lower_hex_digit (byte lsr 4));
      Bytes.set s (!k + 1) (lower_hex_digit byte);
      (if !i <> max && slen <> 0 then Bytes.set s (!k + 2) sep);
      incr i; k := !k + 2 + slen;
    done;
    Bytes.unsafe_to_string s

  let pp ppf b =
    let max = length b - 1 in
    for i = 0 to max do
      let byte = get b i in
      Format.pp_print_char ppf (lower_hex_digit (byte lsr 4));
      Format.pp_print_char ppf (lower_hex_digit byte);
      (if i <> max then Format.pp_print_char ppf ' ');
    done
end

module Bytes_bytes = struct
  type t = Bytes.t
  let _create n = Bytes.create n
  let create n ~init:v = Bytes.make n (Char.chr v)
  let init n ~init = Bytes.init n (fun i -> Char.chr (init i))
  let[@inline] length b = Bytes.length b
  let[@inline] get b i = Bytes.get_uint8 b i
  let[@inline] set b i v = Bytes.set_uint8 b i v
  let copy = Bytes.copy
  let clear b = Bytes.fill b 0 (Bytes.length b) '\x00'
  let blit ~src i ~dst k ~len = Bytes.blit src i dst k len
  let[@inline] check_length b len =
    let fnd = length b in
    if fnd <> len then raise (Invalid_argument (err_length ~exp:len ~fnd))

  let of_string = Bytes.of_string
  let to_string = Bytes.to_string
  let of_bytes = Bytes.copy
  let to_bytes = Bytes.copy
  let of_bigbytes = Bytes_bigbytes.to_bytes
  let to_bigbytes = Bytes_bigbytes.of_bytes

  type nonrec hex_error = hex_error =
  | Odd_hex_digits | Illegal_char of Char.t * int

  let hex_error_message = hex_error_message
  let of_hex s = match hex_is_valid s with
  | Error _ as e -> e
  | Ok len ->
      let b = _create len in
      let rec find_hex_digit s k = match s.[k] with
      | '0' .. '9' | 'A' .. 'F' | 'a' .. 'f' -> k
      | _ -> find_hex_digit s (k + 1)
      in
      let rec loop b i max s k = match i > max with
      | true -> Ok b
      | false ->
          let k = find_hex_digit s k in
          let hi = hex_digit_value s.[k] in
          let k = find_hex_digit s (k + 1) in
          let lo = hex_digit_value s.[k] in
          set b i ((hi lsl 4) lor lo);
          loop b (i + 1) max s (k + 1)
      in
      loop b 0 (len - 1) s 0

  let of_hex' s = Result.map_error hex_error_message (of_hex s)
  let to_hex ?sep b =
    let blen = length b in
    let slen, sep = match sep with None -> 0, '\x00' | Some sep -> 1, sep in
    let s = Bytes.create (blen * 2 + (blen - 1) * slen) in
    let max = blen - 1 and i = ref 0 and k = ref 0 in
    while (!i <= max) do
      let byte = get b !i in
      Bytes.set s !k (lower_hex_digit (byte lsr 4));
      Bytes.set s (!k + 1) (lower_hex_digit byte);
      (if !i <> max && slen <> 0 then Bytes.set s (!k + 2) sep);
      incr i; k := !k + 2 + slen;
    done;
    Bytes.unsafe_to_string s

  let pp ppf b =
    let max = length b - 1 in
    for i = 0 to max do
      let byte = get b i in
      Format.pp_print_char ppf (lower_hex_digit (byte lsr 4));
      Format.pp_print_char ppf (lower_hex_digit byte);
      (if i <> max then Format.pp_print_space ppf ());
    done
end

(* Crypto *)

(* The module has no hardcoded constants, they are all sourced from
   the C part via these functions. *)

external box_publickeybytes : unit -> int =
  "ocaml_ttnacl_crypto_box_publickeybytes"

external box_secretkeybytes : unit -> int =
  "ocaml_ttnacl_crypto_box_secretkeybytes"

external box_beforenmbytes : unit -> int =
  "ocaml_ttnacl_crypto_box_beforenmbytes"

external box_noncebytes : unit -> int =
  "ocaml_ttnacl_crypto_box_noncebytes"

external box_zerobytes : unit -> int =
  "ocaml_ttnacl_crypto_box_zerobytes"

external box_boxzerobytes : unit -> int =
  "ocaml_ttnacl_crypto_box_boxzerobytes"

external scalarmult_bytes : unit -> int =
  "ocaml_ttnacl_crypto_scalarmult_bytes"

external scalarmult_scalarbytes : unit -> int =
  "ocaml_ttnacl_crypto_scalarmult_scalarbytes"

external sign_publickeybytes : unit -> int =
  "ocaml_ttnacl_crypto_sign_publickeybytes"

external sign_secretkeybytes : unit -> int =
  "ocaml_ttnacl_crypto_sign_secretkeybytes"

external sign_bytes : unit -> int =
  "ocaml_ttnacl_crypto_sign_bytes"

external secretbox_keybytes : unit -> int =
  "ocaml_ttnacl_crypto_secretbox_keybytes"

external secretbox_noncebytes : unit -> int =
  "ocaml_ttnacl_crypto_secretbox_noncebytes"

external secretbox_zerobytes : unit -> int =
  "ocaml_ttnacl_crypto_secretbox_zerobytes"

external secretbox_boxzerobytes : unit -> int =
  "ocaml_ttnacl_crypto_secretbox_boxzerobytes"

external stream_keybytes : unit -> int =
  "ocaml_ttnacl_crypto_stream_keybytes"

external stream_noncebytes : unit -> int =
  "ocaml_ttnacl_crypto_stream_noncebytes"

external onetimeauth_keybytes : unit -> int =
  "ocaml_ttnacl_crypto_onetimeauth_keybytes"

external onetimeauth_bytes : unit -> int =
  "ocaml_ttnacl_crypto_onetimeauth_bytes"

external hash_bytes : unit -> int =
  "ocaml_ttnacl_crypto_hash_bytes"

let box_publickeybytes = box_publickeybytes ()
let box_secretkeybytes = box_secretkeybytes ()
let box_beforenmbytes = box_beforenmbytes ()
let box_noncebytes = box_noncebytes ()
let box_zerobytes = box_zerobytes ()
let box_boxzerobytes = box_boxzerobytes ()
let scalarmult_bytes  = scalarmult_bytes ()
let scalarmult_scalarbytes  = scalarmult_scalarbytes ()
let sign_publickeybytes = sign_publickeybytes ()
let sign_secretkeybytes = sign_secretkeybytes ()
let sign_bytes = sign_bytes ()
let secretbox_keybytes = secretbox_keybytes ()
let secretbox_noncebytes = secretbox_noncebytes ()
let secretbox_zerobytes = secretbox_zerobytes ()
let secretbox_boxzerobytes = secretbox_boxzerobytes ()
let stream_keybytes = stream_keybytes ()
let stream_noncebytes = stream_noncebytes ()
let onetimeauth_keybytes = onetimeauth_keybytes ()
let onetimeauth_bytes = onetimeauth_bytes ()
let hash_bytes = hash_bytes ()

let box_cipher_text_overhead_length = box_zerobytes - box_boxzerobytes
let secretbox_cipher_text_overhead_length =
  secretbox_zerobytes - secretbox_boxzerobytes

module type BYTES_OBJ = sig (* Not exposed, avoids repetitions *)
  type bytes
  type t
  val length : int
  val equal : t -> t -> bool
  val of_bytes : bytes -> t
  val to_bytes : t -> bytes
  val pp : Format.formatter -> t -> unit
end

module type GENERABLE_BYTES_OBJ = sig (* Not exposed, avoids repetitions *)
  type bytes
  type t
  val length : int
  val generate : unit -> t
  val equal : t -> t -> bool
  val of_bytes : bytes -> t
  val to_bytes : t -> bytes
  val pp : Format.formatter -> t -> unit
end

module type CRYPTO = sig
  module Bytes : BYTES
  module Entropy : sig val gather : int -> Bytes.t end
  module Box : sig
    module Public_key : BYTES_OBJ with type bytes := Bytes.t
    module Secret_key : BYTES_OBJ with type bytes := Bytes.t
    val keypair : unit -> Public_key.t * Secret_key.t
    module Nonce : GENERABLE_BYTES_OBJ with type bytes := Bytes.t
    type plain_text = Bytes.t
    type cipher_text = Bytes.t
    val cipher_text_overhead_length : int
    val box :
      receiver:Public_key.t -> sender:Secret_key.t -> nonce:Nonce.t ->
      plain_text:plain_text -> cipher_text
    val open' :
      sender:Public_key.t -> receiver:Secret_key.t -> nonce:Nonce.t ->
      cipher_text:cipher_text -> plain_text option
    module Shared_secret_key : BYTES_OBJ with type bytes := Bytes.t
    val before : Public_key.t -> Secret_key.t -> Shared_secret_key.t
    val box_after :
      shared_secret_key:Shared_secret_key.t -> nonce:Nonce.t ->
      plain_text:plain_text -> cipher_text
    val open_after :
      shared_secret_key:Shared_secret_key.t -> nonce:Nonce.t ->
      cipher_text:cipher_text -> plain_text option
  end
  module Scalarmult : sig
    type scalar = Bytes.t
    val scalar_length : int
    type group_element = Bytes.t
    val group_element_length : int
    val mult : scalar -> group_element -> group_element
    val base : scalar -> group_element
  end
  module Sign : sig
    module Public_key : BYTES_OBJ with type bytes := Bytes.t
    module Secret_key : BYTES_OBJ with type bytes := Bytes.t
    val keypair : unit -> Public_key.t * Secret_key.t
    type plain_text = Bytes.t
    type signed_text = Bytes.t
    val signed_text_max_overhead_length : int
    val sign : secret_key:Secret_key.t -> plain_text:plain_text -> signed_text
    val open' :
      public_key:Public_key.t -> signed_text:signed_text -> plain_text option
  end
  module Secretbox : sig
    module Secret_key : GENERABLE_BYTES_OBJ with type bytes := Bytes.t
    module Nonce : GENERABLE_BYTES_OBJ with type bytes := Bytes.t
    type plain_text = Bytes.t
    type cipher_text = Bytes.t
    val cipher_text_overhead_length : int
    val box :
      secret_key:Secret_key.t -> nonce:Nonce.t -> plain_text:plain_text ->
      cipher_text
    val open' :
      secret_key:Secret_key.t -> nonce:Nonce.t -> cipher_text:cipher_text ->
      plain_text option
  end
  module Stream : sig
    module Secret_key : GENERABLE_BYTES_OBJ with type bytes := Bytes.t
    module Nonce : GENERABLE_BYTES_OBJ with type bytes := Bytes.t
    val stream :
      secret_key:Secret_key.t -> nonce:Nonce.t -> length:int -> Bytes.t
    val xor :
      secret_key:Secret_key.t -> nonce:Nonce.t -> stream:Bytes.t -> Bytes.t
  end
  module Onetimeauth : sig
    module Secret_key : GENERABLE_BYTES_OBJ with type bytes := Bytes.t
    module Authenticator : BYTES_OBJ with type bytes := Bytes.t
    val auth : secret_key:Secret_key.t -> Bytes.t -> Authenticator.t
    val verify :
      secret_key:Secret_key.t -> auth:Authenticator.t -> Bytes.t -> bool
  end
  module Hash : sig
    type t
    val length : int
    val hash : Bytes.t -> t
    val of_bytes : Bytes.t -> t
    val to_bytes : t -> Bytes.t
    val equal : t -> t -> bool
    val pp : Format.formatter -> t -> unit
  end
  module Verify : sig
    val bytes : Bytes.t -> Bytes.t -> bool
    val bytes_16 : Bytes.t -> Bytes.t -> bool
    val bytes_32 : Bytes.t -> Bytes.t -> bool
  end
end

(* Crypto on bigbytes *)

module Bigcrypto = struct
  module Bytes = Bytes_bigbytes

  let encryption_buffers ~plain_text ~zero_length = (* add padding *)
    let plain_len = Bytes.length plain_text in
    let m = Bytes.create (zero_length + plain_len) ~init:0 in
    let c = Bytes._create (Bytes.length m) in
    Bytes.blit ~src:plain_text 0 ~dst:m zero_length ~len:plain_len;
    c, m

  let buffer_to_cipher_text c ~boxzero_length = (* drop padding *)
    let cipher_len = Bytes.length c - boxzero_length in
    Bigarray.Array1.sub c boxzero_length cipher_len

  let decryption_buffers ~cipher_text ~boxzero_length = (* add padding *)
    let cipher_len = Bytes.length cipher_text in
    let c = Bytes.create (boxzero_length + cipher_len) ~init:0 in
    let m = Bytes._create (Bytes.length c) in
    Bytes.blit ~src:cipher_text 0 ~dst:c boxzero_length ~len:cipher_len;
    m, c

  let buffer_to_plain_text m ~zero_length = (* drop padding *)
    let plain_len = Bytes.length m - box_zerobytes in
    Bigarray.Array1.sub m zero_length plain_len

  module Entropy = struct
    external _gather : Bytes.t -> unit = "ocaml_ttnacl_bigentropy_gather"
    let gather n = let b = Bytes._create n in _gather b; b
  end

  module Verify = struct
    external _bytes : Bytes.t -> Bytes.t -> bool =
      "ocaml_ttnacl_bigcrypto_verify_n"

    external _bytes_16 : Bytes.t -> Bytes.t -> bool =
      "ocaml_ttnacl_bigcrypto_verify_16"

    external _bytes_32 : Bytes.t -> Bytes.t -> bool =
      "ocaml_ttnacl_bigcrypto_verify_32"

    let bytes b0 b1 =
      let len = Bytes.length b0 in Bytes.check_length b1 len; _bytes b0 b1

    let bytes_16 b0 b1 =
      Bytes.check_length b0 16; Bytes.check_length b1 16; _bytes_16 b0 b1

    let bytes_32 b0 b1 =
      Bytes.check_length b0 32; Bytes.check_length b1 32; _bytes_32 b0 b1
  end

  module Box = struct
    module Public_key = struct
      type t = Bytes.t
      let length = box_publickeybytes
      let equal = Verify.bytes
      let of_bytes b = Bytes.check_length b length; b
      let to_bytes = Fun.id
      let pp = pp_labelled_bytes Bytes.pp "pk"
    end

    module Secret_key = struct
      type t = Bytes.t
      let length = box_secretkeybytes
      let equal = Verify.bytes
      let of_bytes b = Bytes.check_length b length; b
      let to_bytes = Fun.id
      let pp = pp_labelled_bytes Bytes.pp "sk"
    end

    external _keypair : Public_key.t -> Secret_key.t -> unit =
      "ocaml_ttnacl_bigcrypto_box_keypair"

    let keypair () =
      let pk = Bytes._create Public_key.length in
      let sk = Bytes._create Secret_key.length in
      _keypair pk sk; pk, sk

    module Nonce = struct
      type t = Bytes.t
      let length = box_noncebytes
      let generate () = Entropy.gather length
      let equal = Verify.bytes
      let of_bytes b = Bytes.check_length b length; b
      let to_bytes = Fun.id
      let pp = pp_labelled_bytes Bytes.pp "nonce"
    end

    type plain_text = Bytes.t
    type cipher_text = Bytes.t
    let cipher_text_overhead_length = box_cipher_text_overhead_length

    external _box :
      cipher_text:cipher_text -> plain_text:plain_text -> nonce:Nonce.t ->
      receiver:Public_key.t -> sender:Secret_key.t -> unit =
      "ocaml_ttnacl_bigcrypto_box"

    external _open :
      plain_text:plain_text -> cipher_text:cipher_text -> nonce:Nonce.t ->
      sender:Public_key.t -> receiver:Secret_key.t -> bool =
      "ocaml_ttnacl_bigcrypto_box_open"

    let zero_length = box_zerobytes
    let boxzero_length = box_boxzerobytes

    let box ~receiver ~sender ~nonce ~plain_text =
      let c, m = encryption_buffers ~plain_text ~zero_length in
      _box ~cipher_text:c ~plain_text:m ~nonce ~receiver ~sender;
      buffer_to_cipher_text c ~boxzero_length

    let open' ~sender ~receiver ~nonce ~cipher_text =
      let m, c = decryption_buffers ~cipher_text ~boxzero_length in
      if _open ~plain_text:m ~cipher_text:c ~nonce ~sender ~receiver
      then Some (buffer_to_plain_text m ~zero_length) else None

    module Shared_secret_key = struct
      type t = Bytes.t
      let length = box_secretkeybytes
      let equal = Verify.bytes
      let of_bytes b = Bytes.check_length b length; b
      let to_bytes = Fun.id
      let pp = pp_labelled_bytes Bytes.pp "sk"
    end

    external _before :
      Shared_secret_key.t -> Public_key.t -> Secret_key.t -> unit =
      "ocaml_ttnacl_bigcrypto_box_before"

    external _box_after :
      cipher_text:cipher_text -> plain_text:plain_text -> nonce:Nonce.t ->
      shared_secret_key:Shared_secret_key.t -> unit =
      "ocaml_ttnacl_bigcrypto_box_after"

    external _open_after :
      plain_text:plain_text -> cipher_text:plain_text -> nonce:Nonce.t ->
      shared_secret_key:Shared_secret_key.t -> bool =
      "ocaml_ttnacl_bigcrypto_box_open_after"

    let before pk sk =
      let ssk = Bytes._create Shared_secret_key.length in
      _before ssk pk sk; ssk

    let box_after ~shared_secret_key ~nonce ~plain_text =
      let c, m = encryption_buffers ~plain_text ~zero_length in
      _box_after ~cipher_text:c ~plain_text:m ~nonce ~shared_secret_key;
      buffer_to_cipher_text c ~boxzero_length

    let open_after ~shared_secret_key ~nonce ~cipher_text =
      let m, c = decryption_buffers ~cipher_text ~boxzero_length in
      if _open_after ~plain_text:m ~cipher_text:c ~nonce ~shared_secret_key
      then Some (buffer_to_plain_text m ~zero_length)
      else None
  end

  module Scalarmult = struct
    type scalar = Bytes.t
    let scalar_length = scalarmult_scalarbytes

    type group_element = Bytes.t
    let group_element_length = scalarmult_bytes

    external _mult : group_element -> scalar -> group_element -> unit =
      "ocaml_ttnacl_bigcrypto_scalarmult"

    external _base : group_element -> scalar -> unit =
      "ocaml_ttnacl_bigcrypto_scalarmult_base"

    let mult n p =
      Bytes.check_length n scalar_length;
      Bytes.check_length p group_element_length;
      let q = Bytes._create group_element_length in
      _mult q n p; q

    let base n =
      Bytes.check_length n scalar_length;
      let q = Bytes._create group_element_length in
      _base q n; q
  end

  module Sign = struct
    module Public_key = struct
      type t = Bytes.t
      let length = sign_publickeybytes
      let equal = Verify.bytes
      let of_bytes b = Bytes.check_length b length; b
      let to_bytes = Fun.id
      let pp = pp_labelled_bytes Bytes.pp "pk"
    end

    module Secret_key = struct
      type t = Bytes.t
      let length = sign_secretkeybytes
      let equal = Verify.bytes
      let of_bytes b = Bytes.check_length b length; b
      let to_bytes = Fun.id
      let pp = pp_labelled_bytes Bytes.pp "sk"
    end

    external _keypair : Public_key.t -> Secret_key.t -> unit =
      "ocaml_ttnacl_bigcrypto_sign_keypair"

    let keypair () =
      let pk = Bytes._create Public_key.length in
      let sk = Bytes._create Secret_key.length in
      _keypair pk sk; pk, sk

    type plain_text = Bytes.t
    type signed_text = Bytes.t
    let signed_text_max_overhead_length = sign_bytes

    external _sign :
      signed_text:signed_text -> plain_text:plain_text ->
      secret_key:Secret_key.t -> int =
      "ocaml_ttnacl_bigcrypto_sign"

    external _open :
      plain_text:plain_text -> signed_text:signed_text ->
      public_key:Public_key.t -> int =
      "ocaml_ttnacl_bigcrypto_sign_open"

    let sign ~secret_key ~plain_text =
      let len = signed_text_max_overhead_length + Bytes.length plain_text in
      let signed_text = Bytes._create len in
      let slen = _sign ~signed_text ~plain_text ~secret_key in
      if slen = len then signed_text else
      Bigarray.Array1.sub signed_text 0 slen

    let open' ~public_key ~signed_text =
      let len = Bytes.length signed_text in
      let plain_text = Bytes._create len in
      let plen = _open ~plain_text ~signed_text ~public_key in
      if plen < 0 then None else
      if plen = len then Some plain_text else
      Some (Bigarray.Array1.sub plain_text 0 plen)
  end

  module Secretbox = struct
    module Secret_key = struct
      type t = Bytes.t
      let length = secretbox_keybytes
      let generate () = Entropy.gather length
      let equal = Verify.bytes
      let of_bytes b = Bytes.check_length b length; b
      let to_bytes = Fun.id
      let pp = pp_labelled_bytes Bytes.pp "sk"
    end

    module Nonce = struct
      type t = Bytes.t
      let length = secretbox_noncebytes
      let generate () = Entropy.gather length
      let equal = Verify.bytes
      let of_bytes b = Bytes.check_length b length; b
      let to_bytes = Fun.id
      let pp = pp_labelled_bytes Bytes.pp "nonce"
    end

    type plain_text = Bytes.t
    type cipher_text = Bytes.t
    let cipher_text_overhead_length = secretbox_cipher_text_overhead_length

    external _box :
      cipher_text:cipher_text -> plain_text:plain_text -> nonce:Nonce.t ->
      secret_key:Secret_key.t -> unit =
      "ocaml_ttnacl_bigcrypto_secretbox"

    external _open :
      plain_text:plain_text -> cipher_text:cipher_text -> nonce:Nonce.t ->
      secret_key:Secret_key.t -> bool =
      "ocaml_ttnacl_bigcrypto_secretbox_open"

    let zero_length = secretbox_zerobytes
    let boxzero_length = secretbox_boxzerobytes

    let box ~secret_key ~nonce ~plain_text =
      let c, m = encryption_buffers ~plain_text ~zero_length in
      _box ~cipher_text:c ~plain_text:m ~nonce ~secret_key;
      buffer_to_cipher_text c ~boxzero_length

    let open' ~secret_key ~nonce ~cipher_text =
      let m, c = decryption_buffers ~cipher_text ~boxzero_length in
      if _open ~plain_text:m ~cipher_text:c ~nonce ~secret_key
      then Some (buffer_to_plain_text m ~zero_length)
      else None
  end

  module Stream = struct
    module Secret_key = struct
      type t = Bytes.t
      let length = stream_keybytes
      let generate () = Entropy.gather length
      let equal = Verify.bytes
      let of_bytes b = Bytes.check_length b length; b
      let to_bytes = Fun.id
      let pp = pp_labelled_bytes Bytes.pp "sk"
    end

    module Nonce = struct
      type t = Bytes.t
      let length = stream_noncebytes
      let generate () = Entropy.gather length
      let equal = Verify.bytes
      let of_bytes b = Bytes.check_length b length; b
      let to_bytes = Fun.id
      let pp = pp_labelled_bytes Bytes.pp "nonce"
    end

    external _stream :
      Bytes.t -> nonce:Nonce.t -> secret_key:Secret_key.t -> unit =
      "ocaml_ttnacl_bigcrypto_stream"

    external _xor :
      Bytes.t -> msg:Bytes.t -> nonce:Nonce.t -> secret_key:Secret_key.t ->
      unit = "ocaml_ttnacl_bigcrypto_stream_xor"

    let stream ~secret_key ~nonce ~length =
      let s = Bytes._create length in
      _stream s ~nonce ~secret_key; s

    let xor ~secret_key ~nonce ~stream:msg =
      let s = Bytes._create (Bytes.length msg) in
      _xor s ~msg ~nonce ~secret_key; s
  end

  module Onetimeauth = struct
    module Secret_key = struct
      type t = Bytes.t
      let length = onetimeauth_keybytes
      let generate () = Entropy.gather length
      let equal = Verify.bytes
      let of_bytes b = Bytes.check_length b length; b
      let to_bytes = Fun.id
      let pp = pp_labelled_bytes Bytes.pp "sk"
    end

    module Authenticator = struct
      type t = Bytes.t
      let length = onetimeauth_bytes
      let equal = Verify.bytes
      let of_bytes b = Bytes.check_length b length; b
      let to_bytes = Fun.id
      let pp = pp_labelled_bytes Bytes.pp "auth"
    end

    external _auth :
      auth:Authenticator.t -> Bytes.t -> secret_key:Secret_key.t -> unit =
      "ocaml_ttnacl_bigcrypto_onetimeauth"

    external _verify :
      auth:Authenticator.t -> Bytes.t -> secret_key:Secret_key.t -> bool =
      "ocaml_ttnacl_bigcrypto_onetimeauth_verify"

    let auth ~secret_key b =
      let auth = Bytes._create Authenticator.length in
      _auth ~auth b ~secret_key; auth

    let verify ~secret_key ~auth b = _verify ~auth b ~secret_key
  end

  module Hash = struct
    type t = Bytes.t
    let length = hash_bytes
    let equal = Verify.bytes
    external _hash : t -> Bytes.t -> unit = "ocaml_ttnacl_bigcrypto_hash"
    let hash m = let h = Bytes._create length in _hash h m; h
    let of_bytes b = Bytes.check_length b length; b
    let to_bytes = Fun.id
    let pp ppf h = Format.fprintf ppf "sha512=%s" (Bytes.to_hex h)
  end
end

(* Crypto on bytes *)

module Crypto = struct
  module Bytes = Bytes_bytes

  let encryption_buffers ~plain_text ~zero_length = (* add padding *)
    let plain_len = Bytes.length plain_text in
    let m = Bytes.create (zero_length + plain_len) ~init:0 in
    let c = Bytes._create (Bytes.length m) in
    Bytes.blit ~src:plain_text 0 ~dst:m zero_length ~len:plain_len;
    c, m

  let buffer_to_cipher_text c ~boxzero_length = (* drop padding *)
    let cipher_len = Bytes.length c - boxzero_length in
    Stdlib.Bytes.sub c boxzero_length cipher_len

  let decryption_buffers ~cipher_text ~boxzero_length = (* add padding *)
    let cipher_len = Bytes.length cipher_text in
    let c = Bytes.create (boxzero_length + cipher_len) ~init:0 in
    let m = Bytes._create (Bytes.length c) in
    Bytes.blit ~src:cipher_text 0 ~dst:c boxzero_length ~len:cipher_len;
    m, c

  let buffer_to_plain_text m ~zero_length = (* drop padding *)
    let plain_len = Bytes.length m - box_zerobytes in
    Stdlib.Bytes.sub m zero_length plain_len

  module Entropy = struct
    external _gather : Bytes.t -> unit = "ocaml_ttnacl_entropy_gather"
    let gather n = let b = Bytes._create n in _gather b; b
  end

  module Verify = struct
    external _bytes : Bytes.t -> Bytes.t -> bool =
      "ocaml_ttnacl_crypto_verify_n"

    external _bytes_16 : Bytes.t -> Bytes.t -> bool =
      "ocaml_ttnacl_crypto_verify_16"

    external _bytes_32 : Bytes.t -> Bytes.t -> bool =
      "ocaml_ttnacl_crypto_verify_32"

    let bytes b0 b1 =
      let len = Bytes.length b0 in Bytes.check_length b1 len; _bytes b0 b1

    let bytes_16 b0 b1 =
      Bytes.check_length b0 16; Bytes.check_length b1 16; _bytes_16 b0 b1

    let bytes_32 b0 b1 =
      Bytes.check_length b0 32; Bytes.check_length b1 32; _bytes_32 b0 b1
  end

  module Box = struct
    module Public_key = struct
      type t = Bytes.t
      let length = box_publickeybytes
      let equal = Verify.bytes
      let of_bytes b = Bytes.check_length b length; b
      let to_bytes = Fun.id
      let pp = pp_labelled_bytes Bytes.pp "pk"
    end

    module Secret_key = struct
      type t = Bytes.t
      let length = box_secretkeybytes
      let equal = Verify.bytes
      let of_bytes b = Bytes.check_length b length; b
      let to_bytes = Fun.id
      let pp = pp_labelled_bytes Bytes.pp "sk"
    end

    external _keypair : Public_key.t -> Secret_key.t -> unit =
      "ocaml_ttnacl_crypto_box_keypair"

    let keypair () =
      let pk = Bytes._create Public_key.length in
      let sk = Bytes._create Secret_key.length in
      _keypair pk sk; pk, sk

    module Nonce = struct
      type t = Bytes.t
      let length = box_noncebytes
      let generate () = Entropy.gather length
      let equal = Verify.bytes
      let of_bytes b = Bytes.check_length b length; b
      let to_bytes = Fun.id
      let pp = pp_labelled_bytes Bytes.pp "nonce"
    end

    type plain_text = Bytes.t
    type cipher_text = Bytes.t
    let cipher_text_overhead_length = box_cipher_text_overhead_length

    external _box :
      cipher_text:cipher_text -> plain_text:plain_text -> nonce:Nonce.t ->
      receiver:Public_key.t -> sender:Secret_key.t -> unit =
      "ocaml_ttnacl_crypto_box"

    external _open :
      plain_text:plain_text -> cipher_text:cipher_text -> nonce:Nonce.t ->
      sender:Public_key.t -> receiver:Secret_key.t -> bool =
      "ocaml_ttnacl_crypto_box_open"

    let zero_length = box_zerobytes
    let boxzero_length = box_boxzerobytes

    let box ~receiver ~sender ~nonce ~plain_text =
      let c, m = encryption_buffers ~plain_text ~zero_length in
      _box ~cipher_text:c ~plain_text:m ~nonce ~receiver ~sender;
      buffer_to_cipher_text c ~boxzero_length

    let open' ~sender ~receiver ~nonce ~cipher_text =
      let m, c = decryption_buffers ~cipher_text ~boxzero_length in
      if _open ~plain_text:m ~cipher_text:c ~nonce ~sender ~receiver
      then Some (buffer_to_plain_text m ~zero_length) else None

    module Shared_secret_key = struct
      type t = Bytes.t
      let length = box_secretkeybytes
      let equal = Verify.bytes
      let of_bytes b = Bytes.check_length b length; b
      let to_bytes = Fun.id
      let pp = pp_labelled_bytes Bytes.pp "sk"
    end

    external _before :
      Shared_secret_key.t -> Public_key.t -> Secret_key.t -> unit =
      "ocaml_ttnacl_crypto_box_before"

    external _box_after :
      cipher_text:cipher_text -> plain_text:plain_text -> nonce:Nonce.t ->
      shared_secret_key:Shared_secret_key.t -> unit =
      "ocaml_ttnacl_crypto_box_after"

    external _open_after :
      plain_text:plain_text -> cipher_text:plain_text -> nonce:Nonce.t ->
      shared_secret_key:Shared_secret_key.t -> bool =
      "ocaml_ttnacl_crypto_box_open_after"

    let before pk sk =
      let ssk = Bytes._create Shared_secret_key.length in
      _before ssk pk sk; ssk

    let box_after ~shared_secret_key ~nonce ~plain_text =
      let c, m = encryption_buffers ~plain_text ~zero_length in
      _box_after ~cipher_text:c ~plain_text:m ~nonce ~shared_secret_key;
      buffer_to_cipher_text c ~boxzero_length

    let open_after ~shared_secret_key ~nonce ~cipher_text =
      let m, c = decryption_buffers ~cipher_text ~boxzero_length in
      if _open_after ~plain_text:m ~cipher_text:c ~nonce ~shared_secret_key
      then Some (buffer_to_plain_text m ~zero_length)
      else None
  end

  module Scalarmult = struct
    type scalar = Bytes.t
    let scalar_length = scalarmult_scalarbytes

    type group_element = Bytes.t
    let group_element_length = scalarmult_bytes

    external _mult : group_element -> scalar -> group_element -> unit =
      "ocaml_ttnacl_crypto_scalarmult"

    external _base : group_element -> scalar -> unit =
      "ocaml_ttnacl_crypto_scalarmult_base"

    let mult n p =
      Bytes.check_length n scalar_length;
      Bytes.check_length p group_element_length;
      let q = Bytes._create group_element_length in
      _mult q n p; q

    let base n =
      Bytes.check_length n scalar_length;
      let q = Bytes._create group_element_length in
      _base q n; q
  end

  module Sign = struct
    module Public_key = struct
      type t = Bytes.t
      let length = sign_publickeybytes
      let equal = Verify.bytes
      let of_bytes b = Bytes.check_length b length; b
      let to_bytes = Fun.id
      let pp = pp_labelled_bytes Bytes.pp "pk"
    end

    module Secret_key = struct
      type t = Bytes.t
      let length = sign_secretkeybytes
      let equal = Verify.bytes
      let of_bytes b = Bytes.check_length b length; b
      let to_bytes = Fun.id
      let pp = pp_labelled_bytes Bytes.pp "sk"
    end
    external _keypair : Public_key.t -> Secret_key.t -> unit =
      "ocaml_ttnacl_crypto_sign_keypair"

    let keypair () =
      let pk = Bytes._create Public_key.length in
      let sk = Bytes._create Secret_key.length in
      _keypair pk sk; pk, sk

    type plain_text = Bytes.t
    type signed_text = Bytes.t
    let signed_text_max_overhead_length = sign_bytes

    external _sign :
      signed_text:signed_text -> plain_text:plain_text ->
      secret_key:Secret_key.t -> int =
      "ocaml_ttnacl_crypto_sign"

    external _open :
      plain_text:plain_text -> signed_text:signed_text ->
      public_key:Public_key.t -> int =
      "ocaml_ttnacl_crypto_sign_open"

    let sign ~secret_key ~plain_text =
      let len = signed_text_max_overhead_length + Bytes.length plain_text in
      let signed_text = Bytes._create len in
      let slen = _sign ~signed_text ~plain_text ~secret_key in
      if slen = len then signed_text else
      Stdlib.Bytes.sub signed_text 0 slen

    let open' ~public_key ~signed_text =
      let len = Bytes.length signed_text in
      let plain_text = Bytes._create len in
      let plen = _open ~plain_text ~signed_text ~public_key in
      if plen < 0 then None else
      if plen = len then Some plain_text else
      Some (Stdlib.Bytes.sub plain_text 0 plen)
    end

  module Secretbox = struct
    module Secret_key = struct
      type t = Bytes.t
      let length = secretbox_keybytes
      let generate () = Entropy.gather length
      let equal = Verify.bytes
      let of_bytes b = Bytes.check_length b length; b
      let to_bytes = Fun.id
      let pp = pp_labelled_bytes Bytes.pp "sk"
    end

    module Nonce = struct
      type t = Bytes.t
      let length = secretbox_noncebytes
      let generate () = Entropy.gather length
      let equal = Verify.bytes
      let of_bytes b = Bytes.check_length b length; b
      let to_bytes = Fun.id
      let pp = pp_labelled_bytes Bytes.pp "nonce"
    end

    type plain_text = Bytes.t
    type cipher_text = Bytes.t
    let cipher_text_overhead_length = secretbox_cipher_text_overhead_length

    external _box :
      cipher_text:cipher_text -> plain_text:plain_text -> nonce:Nonce.t ->
      secret_key:Secret_key.t -> unit =
      "ocaml_ttnacl_crypto_secretbox"

    external _open :
      plain_text:plain_text -> cipher_text:cipher_text -> nonce:Nonce.t ->
      secret_key:Secret_key.t -> bool =
      "ocaml_ttnacl_crypto_secretbox_open"

    let zero_length = secretbox_zerobytes
    let boxzero_length = secretbox_boxzerobytes

    let box ~secret_key ~nonce ~plain_text =
      let c, m = encryption_buffers ~plain_text ~zero_length in
      _box ~cipher_text:c ~plain_text:m ~nonce ~secret_key;
      buffer_to_cipher_text c ~boxzero_length

    let open' ~secret_key ~nonce ~cipher_text =
      let m, c = decryption_buffers ~cipher_text ~boxzero_length in
      if _open ~plain_text:m ~cipher_text:c ~nonce ~secret_key
      then Some (buffer_to_plain_text m ~zero_length)
      else None
  end

  module Stream = struct
    module Secret_key = struct
      type t = Bytes.t
      let length = stream_keybytes
      let generate () = Entropy.gather length
      let equal = Verify.bytes
      let of_bytes b = Bytes.check_length b length; b
      let to_bytes = Fun.id
      let pp = pp_labelled_bytes Bytes.pp "sk"
    end

    module Nonce = struct
      type t = Bytes.t
      let length = stream_noncebytes
      let generate () = Entropy.gather length
      let equal = Verify.bytes
      let of_bytes b = Bytes.check_length b length; b
      let to_bytes = Fun.id
      let pp = pp_labelled_bytes Bytes.pp "nonce"
    end

    external _stream :
      Bytes.t -> nonce:Nonce.t -> secret_key:Secret_key.t -> unit =
      "ocaml_ttnacl_crypto_stream"

    external _xor :
      Bytes.t -> msg:Bytes.t -> nonce:Nonce.t -> secret_key:Secret_key.t ->
      unit = "ocaml_ttnacl_crypto_stream_xor"

    let stream ~secret_key ~nonce ~length =
      let s = Bytes._create length in
      _stream s ~nonce ~secret_key; s

    let xor ~secret_key ~nonce ~stream:msg =
      let s = Bytes._create (Bytes.length msg) in
      _xor s ~msg ~nonce ~secret_key; s
  end

  module Onetimeauth = struct
    module Secret_key = struct
      type t = Bytes.t
      let length = onetimeauth_keybytes
      let generate () = Entropy.gather length
      let equal = Verify.bytes
      let of_bytes b = Bytes.check_length b length; b
      let to_bytes = Fun.id
      let pp = pp_labelled_bytes Bytes.pp "sk"
    end

    module Authenticator = struct
      type t = Bytes.t
      let length = onetimeauth_bytes
      let equal = Verify.bytes
      let of_bytes b = Bytes.check_length b length; b
      let to_bytes = Fun.id
      let pp = pp_labelled_bytes Bytes.pp "auth"
    end

    external _auth :
      auth:Authenticator.t -> Bytes.t -> secret_key:Secret_key.t -> unit =
      "ocaml_ttnacl_crypto_onetimeauth"

    external _verify :
      auth:Authenticator.t -> Bytes.t -> secret_key:Secret_key.t -> bool =
      "ocaml_ttnacl_crypto_onetimeauth_verify"

    let auth ~secret_key b =
      let auth = Bytes._create Authenticator.length in
      _auth ~auth b ~secret_key; auth

    let verify ~secret_key ~auth b = _verify ~auth b ~secret_key
  end

  module Hash = struct
    type t = Bytes.t
    let length = hash_bytes
    let equal = Verify.bytes
    external _hash : t -> Bytes.t -> unit = "ocaml_ttnacl_crypto_hash"
    let hash m = let h = Bytes._create length in _hash h m; h
    let of_bytes b = Bytes.check_length b length; b
    let to_bytes = Fun.id
    let pp ppf h = Format.fprintf ppf "sha512=%s" (Bytes.to_hex h)
  end
end

(*---------------------------------------------------------------------------
   Copyright (c) 2022 The ttweetnacl programmers

   Permission to use, copy, modify, and/or distribute this software for any
   purpose with or without fee is hereby granted, provided that the above
   copyright notice and this permission notice appear in all copies.

   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
  ---------------------------------------------------------------------------*)
