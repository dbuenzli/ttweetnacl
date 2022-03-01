(*---------------------------------------------------------------------------
   Copyright (c) 2022 The ttweetnacl programmers. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

(** TweetNaCl cryptography.

    The binding exposes two modules with the same signature except
    for the type used for storing bytes:

    {ul
    {- {!Bigcrypto} uses {{!bigbytes}bigbytes} values which are managed
       by the C allocator. Calls to the C primitives may {{:https://ocaml.org/manual/intfc.html#ss:parallel-execution-long-running-c-code}
       release the runtime system} when deemed appropriate.}
    {- {!Crypto} uses [bytes] values which are managed by the OCaml
       garbage collector and thus may be copied around in memory – you may
       care, or not. Calls to the C primitives never release the runtime
       system.}}

    {b References.}
    {ul
    {- The {{:https://tweetnacl.cr.yp.to/}TweetNaCl website} and
       {{:https://tweetnacl.cr.yp.to/tweetnacl-20140917.pdf}paper}.}
    {- The {{:https://nacl.cr.yp.to/}NaCl documentation}.}} *)

(* These functions have been left out for now. They could be added if
   one has a use for them.

   crypto_core_salsa20
   crypto_core_hsalsa20
   crypto_stream_salsa20
   crypto_stream_salsa20_xor
   crypto_auth = crypto_auth_hmacsha512256
   crypto_auth_verify
   crypto_hashblocks = crypto_hashblocks_sha512 *)

(** {1:bytes Bytes} *)

type bigbytes =
  (int, Bigarray.int8_unsigned_elt, Bigarray.c_layout) Bigarray.Array1.t
(** The type for bigarrays of bytes. *)

(** The module type for byte buffers. *)
module type BYTES = sig
  type t
  (** The type for byte buffers. *)

  val create : int -> init:int -> t
  (** [create n ~init] is a byte buffer of length [n] filled
      with byte [init]. *)

  val init : int -> init:(int -> int) -> t
  (** [init n ~init] is a byte bufer of length [n] with [init i] called
      to initialize index [i]. *)

  val length : t -> int
  (** [length b] is the length of [b]. *)

  val get : t -> int -> int
  (** [get b i] is the byte at index [i] of [b]. *)

  val set : t -> int -> int -> unit
  (** [set b i v] sets the byte at index [i] of [b] to [v]. *)

  val copy : t -> t
  (** [copy b] is a copy of [b]. *)

  val clear : t -> unit
  (** [clear b] fills [b] with [0]. *)

  val blit : src:t -> int -> dst:t -> int -> len:int -> unit
  (** [blit ~src i ~dst k ~len] copies the [len] bytes of [src] starting
      at [i] to those of [dst] starting at [k]. *)

  (** {1:conv Converting} *)

  val of_string : string -> t
  (** [of_string s] are the bytes of [s]. *)

  val to_string : t -> string
  (** [to_string b] are the bytes of [b] as a string. *)

  val of_bytes : bytes -> t
  (** [of_bytes b] are the bytes of [b]. *)

  val to_bytes : t -> bytes
  (** [to_bytes b] are the bytes of [b] as bytes. *)

  val of_bigbytes : bigbytes -> t
  (** [of_bigbytes b] are the bytes of [b]. *)

  val to_bigbytes : t -> bigbytes
  (** [to_bigbytes b] are the bytes of [b] as bigbytes. *)

  (** {2:text Textual} *)

  type hex_error =
  | Odd_hex_digits
  | Illegal_char of Char.t * int (** Character and byte index. *)
  (** The type for textual hexadecimal conversion errors. *)

  val hex_error_message : hex_error -> string
  (** [hex_error_message e] is an english error message for [e]. *)

  val of_hex : string -> (t, hex_error) result
  (** [of_hex s] parses bytes from [s]. Drops space (U+0020) or minus
      (U+002D) characters and then parses any even sequence of
      US-ASCII upper or lowercase hexadecimal digits (U+0030–0+0039,
      U+0041–U+0046, U+0061-U+0066) into a byte sequence.  *)

  val of_hex' : string -> (t, string) result
  (** [of_hex' s] is [Result.map_error hex_error_message (of_hex s)]. *)

  val to_hex : ?sep:char -> t -> string
  (** [to_hex ?sep b] formats [b] as lowercase hexadecimal digits
      with bytes separated by [sep] (if provided; use either [' ']
      or ['-'] if you want to round trip with {!of_hex}). *)

  (** {1:fmt Formatting} *)

  val pp : Format.formatter -> t -> unit
  (** [pp] formats bytes in lowercased hex with a space between
      each byte. *)
end

(** {1:crypto Crypto} *)

(** The module type for NaCl cryptography.

    See the {{:https://nacl.cr.yp.to/}NaCl documentation} for
    more information on how to use the functions. *)
module type CRYPTO = sig

  module Bytes : BYTES
  (** The module for bytes. *)

  (** Entropy gathering (from the OS). *)
  module Entropy : sig
    val gather : int -> Bytes.t
    (** [gather n] gathers [n] bytes of entropy from your operating system.
        The function {b blocks} until enough entropy is gathered.

        The maximal [n] that can be used is platform dependent and
        {!Sys_error} is raised if the request cannot be
        satisfied. However, using no more than 256 bytes should be
        safe.

        This does:
        {ul
        {- {{:https://man.openbsd.org/getentropy}[getentropy]} on Linux, MacOS
           and other unixes that support it.}
        {- {{:https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-rtlgenrandom}[RtlGenRandom]} on Windows
           ({{:https://bugzilla.mozilla.org/show_bug.cgi?id=504270}safe to use}
           despite the availability warning).}
        {- Raise {!Sys_error} otherwise, notably on NetBSD.}}

        Raises {!Sys_error} in case of problem. If this happen do not
        try to handle the exception, log it at the toplevel of your program
        and abort the program. It likely indicates a serious error condition
        in the system. *)
  end

  (** {1:public_key_crypto Public-key cryptography} *)

  (** Public-key authenticated encryption

      The primitive is x25519-xsalsa20-poly1305,
      {{:https://nacl.cr.yp.to/box.html}NaCl documentation}. *)
  module Box : sig

    (** {1:keys_nonces Keys and nonces} *)

    (** Public keys.

        Use {!keypair} to generate one. *)
    module Public_key : sig

      type t
      (** The type for public keys. *)

      val length : int
      (** [length] is the byte length of public keys. *)

      val equal : t -> t -> bool
      (** [equal pk pk'] determines in constant time if [pk] and [pk']
          are bytewise equal. *)

      val of_bytes : Bytes.t -> t
      (** [of_bytes b] is a public key from bytes [b].  Raises
          [Invalid_argument] if [b]'s length differs from
          {!length}. *)

      val to_bytes : t -> Bytes.t
      (** [to_bytes pk] are the bytes of [pk]. *)

      val pp : Format.formatter -> t -> unit
      (** [pp ppf pk] is an unspecified formatter for public keys. *)
    end

    (** Secret keys.

        Use {!keypair} to generate one. *)
    module Secret_key : sig

      type t
      (** The type for secret keys. *)

      val length : int
      (** [length] is the byte length of secret keys. *)

      val equal : t -> t -> bool
      (** [equal sk sk'] determines in constant time if [sk] and [sk']
          are bytewise equal. *)

      val of_bytes : Bytes.t -> t
      (** [of_bytes b] is a secret key from bytes [b].
          Raises [Invalid_argument] if [b]'s length differs from
          {!length}. *)

      val to_bytes : t -> Bytes.t
      (** [to_bytes sk] are the bytes of [sk]. *)

      val pp : Format.formatter -> t -> unit
      (** [pp ppf sk] is an unspecified formatter for secret keys. *)
    end

    val keypair : unit -> Public_key.t * Secret_key.t
    (** [keypair ()] randomly generates a secret key and it corresponding
        public key. The function {b blocks} until enough entropy is gathered. *)

    (** Nonces.

        Use {!Nonce.generate} to generate one. *)
    module Nonce : sig

      type t
      (** The type for nonces. *)

      val length : int
      (** [length] is the byte length of nonces. *)

      val generate : unit -> t
      (** [generate ()] generates a random nonce using {!Entropy.gather}.
          The function {b blocks} until enough entropy is gathered. *)

      val equal : t -> t -> bool
      (** [equal n n'] determines in constant time if [n] and [n']
          are bytewise equal. *)

      val of_bytes : Bytes.t -> t
      (** [of_bytes b] is a nonce from bytes [b]. Raises [Invalid_argument] if
          [n]'s length differs from {!length}. *)

      val to_bytes : t -> Bytes.t
      (** [to_bytes n] are the bytes of [n]. *)

      val pp : Format.formatter -> t -> unit
      (** [pp ppf n] is an unspecified formatter for nonces. *)
    end

    (** {1:box Box} *)

    type plain_text = Bytes.t
    (** The type for plain text. *)

    type cipher_text = Bytes.t
    (** The type for cipher text. *)

    val cipher_text_overhead_length : int
    (** [cipher_text_overhead_length] is the constant additional
        number of bytes a cipher text has over its plain text. *)

    val box :
      receiver:Public_key.t -> sender:Secret_key.t -> nonce:Nonce.t ->
      plain_text:plain_text -> cipher_text
   (** [box ~receiver ~sender ~nonce ~plain_text] is a cipher text
       for [plain_text] encrypted and authenticated by [sender] and [nonce]
       for [receiver].

       {b Note.} The function takes an unpadded plain text and returns an
       unpadded cipher text. *)

    val open' :
      sender:Public_key.t -> receiver:Secret_key.t -> nonce:Nonce.t ->
      cipher_text:cipher_text -> plain_text option
    (** [open' ~sender ~receiver ~nonce ~cipher_text] is:
        {ul
        {- [Some plain_text] if [cipher_text] encrypted by [sender] and
           [nonce] for [receiver] authenticates and decrypts to [plain_text].}
        {- [None] otherwise.}}

        {b Note.} The function takes an unpadded cipher text and
        returns an unpadded plain text. *)

    (** {1:precomp Pre-computation interface} *)

    (** Pre-computed shared secret key.

        Use {!before} to generate one. *)
    module Shared_secret_key : sig

      type t
      (** The type for shared secret keys. *)

      val length : int
      (** [length] is the byte length of shared keys. *)

      val equal : t -> t -> bool
      (** [equal sk sk'] determines in constant time if [sk] and [sk']
          are bytewise equal. *)

      val of_bytes : Bytes.t -> t
      (** [of_bytes b] is a shared secret key from bytes [b].
          Raises [Invalid_argument] if [b]'s length differs from
          {!length}. *)

      val to_bytes : t -> Bytes.t
      (** [to_bytes sk] are the bytes of [sk]. *)

      val pp : Format.formatter -> t -> unit
      (** [pp ppf sk] is an unspecified formatter for secret keys. *)
    end

    val before : Public_key.t -> Secret_key.t -> Shared_secret_key.t
    (** [before pk sk] is a shared secret key for an operation that
        needs [pk] as the public key and [sk] as the secret key. *)

    val box_after :
      shared_secret_key:Shared_secret_key.t -> nonce:Nonce.t ->
      plain_text:plain_text -> cipher_text
   (** [box_after ~shared_secret_key ~nonce ~plain_text] is a cipher text
       for [plain_text] encrypted and authenticated by
       [shared_secret_key] and [nonce].

       The sender is the secret key of [shared_secret_key] and the
       receiver its public key.

       {b Note.} The function takes an unpadded plain text and returns an
       unpadded cipher text. *)

    val open_after :
      shared_secret_key:Shared_secret_key.t -> nonce:Nonce.t ->
      cipher_text:cipher_text -> plain_text option
    (** [open_after ~shared_secret_key ~nonce ~cipher_text] is:
        {ul
        {- [Some plain_text] if [cipher_text] encrypted by [shared_secret_key]
        and [nonce] authenticates and decrypts to [plain_text].}
        {- [None] otherwise.}}

        The sender is the public key of [shared_secret_key] and the receiver
        its secret key.

        {b Note.} The function takes an unpadded cipher text and returns an
        unpadded plain text. *)
  end

  (** Scalar multiplication.

      The primitive is curve25519,
      {{:https://nacl.cr.yp.to/scalarmult.html}NaCl documentation}. *)
  module Scalarmult : sig

    type scalar = Bytes.t
    (** The type for scalars. *)

    val scalar_length : int
    (** [scalar_length] is the byte length of scalars. *)

    type group_element = Bytes.t
    (** The type for group elements. *)

    val group_element_length : int
    (** [group_element_length] is the byte length of group elements. *)

    val mult : scalar -> group_element -> group_element
    (** [mult n p] multiplies [p] by [n]. Raises [Invalid_argument] if
        either [n] or [p] has not the right length. *)

    val base : scalar -> group_element
    (** [base n] multiplies a standard group element by [n]. Raises
        [Invalid_argument] if [n] has not the right length. *)
  end

  (** Signatures.

      The primitive is Ed25519 and SHA-512.
      {{:https://nacl.cr.yp.to/sign.html}NaCl documentation}. *)
  module Sign : sig

    (** {1:keys Keys} *)

    (** Public keys.

        Use {!keypair} to generate one. *)
    module Public_key : sig

      type t
      (** The type for public keys. *)

      val length : int
      (** [length] is the byte length of public keys. *)

      val equal : t -> t -> bool
      (** [equal pk pk'] determines in constant time if [pk] and [pk']
          are bytewise equal. *)

      val of_bytes : Bytes.t -> t
      (** [of_bytes b] is a public key from bytes [b].  Raises
          [Invalid_argument] if [b]'s length differs from
          {!length}. *)

      val to_bytes : t -> Bytes.t
      (** [to_bytes pk] are the bytes of [pk]. *)

      val pp : Format.formatter -> t -> unit
      (** [pp ppf pk] is an unspecified formatter for public keys. *)
    end

    (** Secret keys.

        Use {!keypair} to generate one. *)
    module Secret_key : sig

      type t
      (** The type for secret keys. *)

      val length : int
      (** [length] is the byte length of secret keys. *)

      val equal : t -> t -> bool
      (** [equal sk sk'] determines in constant time if [sk] and [sk']
          are bytewise equal. *)

      val of_bytes : Bytes.t -> t
      (** [of_bytes b] is a secret key from bytes [b].
          Raises [Invalid_argument] if [b]'s length differs from
          {!length}. *)

      val to_bytes : t -> Bytes.t
      (** [to_bytes sk] are the bytes of [sk]. *)

      val pp : Format.formatter -> t -> unit
      (** [pp ppf sk] is an unspecified formatter for secret keys. *)
    end

    val keypair : unit -> Public_key.t * Secret_key.t
    (** [keypair ()] randomly generates a secret key and its corresponding
        public key. The function {b blocks} until enough entropy is gathered. *)

    (** {1:sign Sign} *)

    type plain_text = Bytes.t
    (** The type for unsigned plain text. *)

    type signed_text = Bytes.t
    (** The type for signed text. *)

    val signed_text_max_overhead_length : int
    (** [signed_text_max_overhead_length] is the maximal additional
        number of bytes a signed text has over its plain text. *)

    val sign : secret_key:Secret_key.t -> plain_text:plain_text -> signed_text
    (** [sign ~secret_key ~plain_text] is [plain_text] signed by
        [secret_key]. *)

    val open' :
      public_key:Public_key.t -> signed_text:signed_text -> plain_text option
    (** [open' ~public_key ~signed_text] is:
        {ul
        {- [Some plain_text], if [public_key] successfully verifies the
           signature of [signed_text]. [plain_text] is the verified
           plain text.}
        {- [None] if [public_key] fails to verify the signature of
           [signed_text].}} *)
  end

  (** {1:secret_key_crypto Secret-key cryptography} *)

  (** Secret-key authenticated encryption.

      The primitive is xsalsa20-poly1305,
      {{:https://nacl.cr.yp.to/secretbox.html}NaCl documentation}. *)
  module Secretbox : sig

    (** {1:keys_nonces Keys and nonces} *)

    (** Secret keys.

        Use {!Secret_key.generate} to generate one. *)
    module Secret_key : sig

      type t
      (** The type for secret keys. *)

      val length : int
      (** [length] is the byte length of secret keys. *)

      val generate : unit -> t
      (** [generate ()] generates a random key using {!Entropy.gather}.
          The function {b blocks} until enough entropy is gathered. *)

      val equal : t -> t -> bool
      (** [equal k k'] determines in constant time if [k] and [k']
          are bytewise equal. *)

      val of_bytes : Bytes.t -> t
      (** [of_bytes b] is a secret key from bytes [b].  Raises
          [Invalid_argument] if [b]'s length differs from
          {!length}. *)

      val to_bytes : t -> Bytes.t
      (** [to_bytes k] are the bytes of [k]. *)

      val pp : Format.formatter -> t -> unit
      (** [pp ppf pk] is an unspecified formatter for secret keys. *)
    end

    (** Nonces.

        Use {!Nonce.generate} to generate one. *)
    module Nonce : sig

      type t
      (** The type for nonces. *)

      val length : int
      (** [length] is the byte length of nonces. *)

      val generate : unit -> t
      (** [generate ()] generates a random nonce using {!Entropy.gather}.
          The function {b blocks} until enough entropy is gathered. *)

      val equal : t -> t -> bool
      (** [equal n n'] determines in constant time if [n] and [n']
          are bytewise equal. *)

      val of_bytes : Bytes.t -> t
      (** [of_bytes b] is a nonce from bytes [b]. Raises [Invalid_argument] if
          [n]'s length differs from {!length}. *)

      val to_bytes : t -> Bytes.t
      (** [to_bytes n] are the bytes of [n]. *)

      val pp : Format.formatter -> t -> unit
      (** [pp ppf n] is an unspecified formatter for nonces. *)
    end

    (** {1:box Box} *)

    type plain_text = Bytes.t
    (** The type for plain text. *)

    type cipher_text = Bytes.t
    (** The type for cipher text. *)

    val cipher_text_overhead_length : int
    (** [cipher_text_overhead_length] is the constant additional
        number of bytes a cipher text has over its plain text. *)

    val box :
      secret_key:Secret_key.t -> nonce:Nonce.t -> plain_text:plain_text ->
      cipher_text
    (** [box ~secret_key ~nonce ~plain_text] is a cipher text for
        [plain_text] encrypted and authenticated by [secret_key] and
        [nonce].

        {b Note.} The function takes an unpadded plain text and returns an
        unpadded cipher text. *)

    val open' :
      secret_key:Secret_key.t -> nonce:Nonce.t -> cipher_text:cipher_text ->
      plain_text option
    (** [open' ~secret_key ~nonce ~cipher_text] is:
        {ul
        {- [Some plain_text], if [cipher_text] encrypted by [secret_key]
           and [nonce] authenticates and decrypts to [plain_text].}
        {- [None] otherwise.}}

        {b Note.} The function takes an unpadded cipher text and returns an
        unpadded plain text. *)
  end

  (** Secret-key encryption.

      The primitive is xsalsa20,
      {{:http://nacl.cr.yp.to/stream.html}NaCl documentation}. *)
  module Stream : sig

    (** {1:keys_nonces Keys and nonces} *)

    (** Secret keys.

        Use {!Secret_key.generate} to generate one. *)
    module Secret_key : sig

      type t
      (** The type for secret keys. *)

      val length : int
      (** [length] is the byte length of secret keys. *)

      val generate : unit -> t
      (** [generate ()] generates a random key using {!Entropy.gather}.
          The function {b blocks} until enough entropy is gathered. *)

      val equal : t -> t -> bool
      (** [equal k k'] determines in constant time if [k] and [k']
          are bytewise equal. *)

      val of_bytes : Bytes.t -> t
      (** [of_bytes b] is a secret key from bytes [b].  Raises
          [Invalid_argument] if [b]'s length differs from
          {!length}. *)

      val to_bytes : t -> Bytes.t
      (** [to_bytes k] are the bytes of [k]. *)

      val pp : Format.formatter -> t -> unit
      (** [pp ppf pk] is an unspecified formatter for secret keys. *)
    end

    (** Nonces.

        Use {!Nonce.generate} to generate one. *)
    module Nonce : sig

      type t
      (** The type for nonces. *)

      val length : int
      (** [length] is the byte length of nonces. *)

      val generate : unit -> t
      (** [generate ()] generates a random nonce using {!Entropy.gather}.
          The function {b blocks} until enough entropy is gathered. *)

      val equal : t -> t -> bool
      (** [equal n n'] determines in constant time if [n] and [n']
          are bytewise equal. *)

      val of_bytes : Bytes.t -> t
      (** [of_bytes b] is a nonce from bytes [b]. Raises [Invalid_argument] if
          [n]'s length differs from {!length}. *)

      val to_bytes : t -> Bytes.t
      (** [to_bytes n] are the bytes of [n]. *)

      val pp : Format.formatter -> t -> unit
      (** [pp ppf n] is an unspecified formatter for nonces. *)
    end

    (** {1:cipher Cipher} *)

    val stream :
      secret_key:Secret_key.t -> nonce:Nonce.t -> length:int -> Bytes.t
    (** [stream ~secret_key ~nonce ~length] generates a pseudo-random
        byte stream of length [length] based on [secret_key] and [nonce].
        This can be [xored] with your plain or cipher text to encrypt
        or decrypt. {!xor} does that directly for you. *)

    val xor :
      secret_key:Secret_key.t -> nonce:Nonce.t -> stream:Bytes.t -> Bytes.t
      (** [xor ~secret_key ~nonce ~stream] is the result of encrypting or
          decrypting [stream] using [nonce] and [secret_key]. *)
  end

  (** One-time authentication.

      The primitive is poly1305,
      {{:http://nacl.cr.yp.to/onetimeauth.html}NaCl documentation}. *)
  module Onetimeauth : sig

    (** Secret keys.

        Use {!Secret_key.generate} to generate one. *)
    module Secret_key : sig

      type t
      (** The type for secret keys. *)

      val length : int
      (** [length] is the byte length of secret keys. *)

      val generate : unit -> t
      (** [generate ()] generates a random key using {!Entropy.gather}.
          The function {b blocks} until enough entropy is gathered. *)

      val equal : t -> t -> bool
      (** [equal k k'] determines in constant time if [k] and [k']
          are bytewise equal. *)

      val of_bytes : Bytes.t -> t
      (** [of_bytes b] is a secret key from bytes [b].  Raises
          [Invalid_argument] if [b]'s length differs from
          {!length}. *)

      val to_bytes : t -> Bytes.t
      (** [to_bytes k] are the bytes of [k]. *)

      val pp : Format.formatter -> t -> unit
      (** [pp ppf pk] is an unspecified formatter for secret keys. *)
    end

    (** Authenticators. *)
    module Authenticator : sig
      type t
      (** The type for authenticators. *)

      val length : int
      (** [length] is the byte length of authenticators. *)

      val equal : t -> t -> bool
      (** [equal k k'] determines in constant time if [k] and [k']
          are bytewise equal. *)

      val of_bytes : Bytes.t -> t
      (** [of_bytes b] is an authenticator from bytes [b].  Raises
          [Invalid_argument] if [b]'s length differs from
          {!length}. *)

      val to_bytes : t -> Bytes.t
      (** [to_bytes a] are the bytes of [a]. *)

      val pp : Format.formatter -> t -> unit
      (** [pp ppf a] is an unspecified formatter for authenticators. *)
    end

    val auth : secret_key:Secret_key.t -> Bytes.t -> Authenticator.t
    (** [auth ~secret_key m] is an authenticator for message [m] under
        [secret_key]. *)

    val verify :
      secret_key:Secret_key.t -> auth:Authenticator.t -> Bytes.t -> bool
    (** [verify ~secret_key ~auth m] is [true] iff [auth] is a correct
        authenticator for message [m] under [secret_key]. *)
  end

  (** {1:low Low-level functions} *)

  (** Hashing

      The primitive is SHA-512,
      {{:https://nacl.cr.yp.to/hash.html}NaCl documentation.}. *)
  module Hash : sig

    type t
    (** The type for hashes. *)

    val length : int
    (** [length] is the byte length of hashes. *)

    val hash : Bytes.t -> t
    (** [hash b] hashes bytes [b]. *)

    val of_bytes : Bytes.t -> t
    (** [of_bytes b] is a hash from bytes [b].  Raises
        [Invalid_argument] if [b]'s length differs from
        {!length}. *)

    val to_bytes : t -> Bytes.t
    (** [to_bytes h] are the bytes of [h]. *)

    val equal : t -> t -> bool
    (** [equal h h'] determines in constant time if [h] and [h']
        are bytewise equal. *)

    val pp : Format.formatter -> t -> unit
    (** [pp ppf n] is an unspecified formatter for hashes. *)
  end

  (** Constant time bytes comparison. *)
  module Verify : sig

    val bytes : Bytes.t -> Bytes.t -> bool
    (** [bytes b0 b1] is [true] iff [b0] and [b1] are equal. Raises
        [Invalid_argument] if [b0] or [b1] are not of the same size. *)

    val bytes_16 : Bytes.t -> Bytes.t -> bool
    (** [bytes_16 b0 b1] is [true] iff [b0] and [b1] are equal. Raises
        [Invalid_argument] if [b0] or [b1] not made of 16 bytes. *)

    val bytes_32 : Bytes.t -> Bytes.t -> bool
    (** [bytes_32 b0 b1] is [true] iff [b0] and [b1] are equal. Raises
        [Invalid_argument] if [b0] or [b1] not made of 32 bytes. *)
  end
end

(** Crypto on {!bigbytes}.

    See the {{:https://nacl.cr.yp.to/}NaCl documentation} for
    more information on how to use the functions. *)
module Bigcrypto : CRYPTO with type Bytes.t = bigbytes

(** Crypto on [bytes].

    See the {{:https://nacl.cr.yp.to/}NaCl documentation} for
    more information on how to use the functions. *)
module Crypto : CRYPTO with type Bytes.t = bytes

(*---------------------------------------------------------------------------
   Copyrightb (c) 2022 The ttweetnacl programmers

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
