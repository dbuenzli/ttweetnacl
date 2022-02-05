(*---------------------------------------------------------------------------
   Copyright (c) 2022 The ttweetnacl programmers. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

let pf = Format.fprintf
let pp_str = Format.pp_print_string

let log fmt = Format.kfprintf (Fun.const ()) Format.std_formatter (fmt ^^ "@.")
let log_fail pp ~exp ~fnd =
  log "@[<v3>Expected: @[%a@]@,Found: @[%a@]@]" pp exp pp fnd

(* Asserters *)

let assert_eq' eq pp fnd exp =
  if eq fnd exp then () else (log_fail pp ~exp ~fnd; assert false)

let assert_int = assert_eq' Int.equal Format.pp_print_int
let assert_bool = assert_eq' Bool.equal Format.pp_print_bool
let assert_float = assert_eq' Float.equal Format.pp_print_float
let assert_string =
  let pp_esc_str ppf s = Format.fprintf ppf "%S" s in
  assert_eq' String.equal pp_esc_str

let assert_option eq_some pp_some =
  let eq = Option.equal eq_some in
  let pp ppf = function
  | None -> pf ppf "None"
  | Some v -> pf ppf "Some %a" pp_some v
  in
  assert_eq' eq pp

let assert_result eq_ok pp_ok eq_error pp_error =
  let eq = Result.equal ~ok:eq_ok ~error:eq_error in
  let pp ppf = function
  | Ok v -> pf ppf "Ok %a" pp_ok v
  | Error e -> pf ppf "Error %a" pp_error e
  in
  assert_eq' eq pp

let assert_bytes =
  let pp_bytes ppf b = Format.fprintf ppf "%S" (Bytes.unsafe_to_string b) in
  assert_eq' Bytes.equal pp_bytes

let assert_bigbytes =
  let pp_bigbytes ppf b =
    for i = 0 to Bigarray.Array1.dim b - 1 do
      Format.fprintf ppf "%C" (Char.chr (Bigarray.Array1.get b i));
    done
  in
  assert_eq' ( = ) pp_bigbytes

let assert_invalid_arg f =
  try f (); assert false with Invalid_argument _  -> ()

(* Generating a bit of random stuff (same stuff on each run) *)

let rstate = Random.State.make [|1;2;3;4;5|]
let rbyte _ = Random.State.int rstate 256
let rchar _ = Char.chr (rbyte ())
let rstring n = String.init n rchar
let rbytes n = Bytes.init n rchar
let rbigbytes n = Bigarray.(Array1.init int8_unsigned c_layout n rbyte)

module Test (Crypto : Ttweetnacl.CRYPTO) = struct
  include Crypto

  let rcbytes n = Bytes.init n ~init:(rbyte)
  let bytes_for_alli b p =
    try
      for i = 0 to Bytes.length b - 1 do
        if not (p i (Bytes.get b i)) then raise Exit;
      done;
      true
    with Exit -> false

  let equal_cbytes b0 b1 =
    if Bytes.length b0 <> Bytes.length b1 then false else
    try
      for i = 0 to Bytes.length b0 - 1 do
        if Bytes.get b0 i <> Bytes.get b1 i then raise Exit
      done;
      true
    with Exit -> false

  let assert_cbytes = assert_eq' equal_cbytes Bytes.pp

  (* Tests *)

  let test_to_of_string () =
    log "Testing Bytes.{to,of}_string";
    let s = rstring 46 in
    let b = Bytes.of_string s in
    assert_int (Bytes.length b) (String.length s);
    let eq_s i c = assert_int (Char.code (String.get s i)) c; true in
    assert (bytes_for_alli b eq_s);
    let s' = Bytes.to_string b in
    assert_string s s'

  let test_to_of_bytes () =
    log "Testing Bytes.{to,of}_bytes";
    let by = rbytes 46 in
    let b = Bytes.of_bytes by in
    assert_int (Bytes.length b) (Stdlib.Bytes.length by);
    let eq_by i c = assert_int (Char.code (Stdlib.Bytes.get by i)) c; true in
    assert (bytes_for_alli b eq_by);
    let by' = Bytes.to_bytes b in
    assert_bytes by by'

  let test_to_of_bigbytes () =
    log "Testing Bytes.{to,of}_bigbytes";
    let bb = rbigbytes 46 in
    let b = Bytes.of_bigbytes bb in
    assert_int (Bytes.length b) (Bigarray.Array1.dim bb);
    let eq_bb i c = assert_int (Bigarray.Array1.get bb i) c; true in
    assert (bytes_for_alli b eq_bb);
    let bb' = Bytes.to_bigbytes b in
    assert_bigbytes bb bb'

  let test_to_of_hex () =
    log "Testing Bytes.{to,of}_hex";
    let pp_error ppf e = pp_str ppf (Bytes.hex_error_message e) in
    let eq_error = ( = ) in
    let assert_result = assert_result equal_cbytes Bytes.pp eq_error pp_error in
    let b = rcbytes 45 in
    assert_result (Bytes.of_hex @@ Bytes.to_hex b) (Ok b);
    assert_result (Bytes.of_hex @@ Bytes.to_hex ~sep:' ' b) (Ok b);
    assert_result (Bytes.of_hex @@ Bytes.to_hex ~sep:'-' b) (Ok b);
    assert_result (Bytes.of_hex "aa+cc") (Error (Bytes.Illegal_char ('+', 2)));
    assert_result (Bytes.of_hex "aa c") (Error (Bytes.Odd_hex_digits));
    assert_result (Bytes.of_hex "") (Ok (Bytes.create 0 ~init:0));
    ()

  let test_clear () =
    log "Testing Bytes.clear";
    let s = rstring 55 in
    let b = Bytes.of_string s in
    Bytes.clear b;
    assert (bytes_for_alli b (fun _ byte -> byte = 0))

  let test_entropy () =
    (* This only tests the soundness of the ffi *)
    log "Testing Entropy";
    let b = Entropy.gather 56 in
    assert (Bytes.length b = 56);
    assert_invalid_arg (fun () -> Entropy.gather (-10))

  let test_box () =
    log "Testing Box";
    let sender_pk, sender_sk = Box.keypair () in
    let receiver_pk, receiver_sk = Box.keypair () in
    let nonce = Box.Nonce.generate () in
    assert (Box.Public_key.equal sender_pk sender_pk);
    assert (not (Box.Public_key.equal sender_pk receiver_pk));
    assert (Box.Secret_key.equal sender_sk sender_sk);
    assert (not (Box.Secret_key.equal sender_sk receiver_sk));
    assert Box.Public_key.(length = Bytes.length @@ to_bytes sender_pk);
    assert Box.Secret_key.(length = Bytes.length @@ to_bytes sender_sk);
    assert Box.Nonce.(length = Bytes.length @@ to_bytes nonce);
    let plain_text = Bytes.of_string "Why is that so secret ?" in
    let cipher_text =
      Box.box ~receiver:receiver_pk ~sender:sender_sk ~nonce ~plain_text
    in
    let dec =
      Box.open' ~sender:sender_pk ~receiver:receiver_sk ~nonce ~cipher_text
    in
    let invalid_dec =
      Box.open' ~sender:sender_pk ~receiver:sender_sk ~nonce ~cipher_text
    in
    assert (not (equal_cbytes cipher_text plain_text));
    (match dec with
    | None -> assert false | Some p -> assert_cbytes p plain_text);
    (match invalid_dec with | None -> () | Some _ -> assert false);
    (* Same with shared secret key *)
    let enc_ssk = Box.before receiver_pk sender_sk in
    let dec_ssk = Box.before sender_pk receiver_sk in
    let cipher_text' =
      Box.box_after ~shared_secret_key:enc_ssk ~nonce ~plain_text
    in
    let dec' =
      Box.open_after ~shared_secret_key:dec_ssk ~nonce ~cipher_text
    in
    let invalid_dec' =
      let k = Box.before sender_pk sender_sk in
      Box.open_after ~shared_secret_key:k ~nonce ~cipher_text
    in
    assert_cbytes cipher_text cipher_text';
    (assert_option equal_cbytes Bytes.pp) dec dec';
    (assert_option equal_cbytes Bytes.pp) invalid_dec invalid_dec';
    ()

  let test_scalarmult () =
    log "Testing Scalarmult.{mult,base}";
    (* Make a Diffie-Hellmann *)
    let x25519 ~public_key:pk ~secret_key:sk = Scalarmult.mult sk pk in
    let gen_keypair () =
      let sk = Entropy.gather Scalarmult.scalar_length in
      Scalarmult.base sk, sk
    in
    let a_pk, a_sk = gen_keypair () in
    let b_pk, b_sk = gen_keypair () in
    let a_x25519 = x25519 ~public_key:b_pk ~secret_key:a_sk in
    let b_x25519 = x25519 ~public_key:a_pk ~secret_key:b_sk in
    assert_cbytes a_x25519 b_x25519;
    ()

  let test_sign () =
    log "Testing Sign";
    let pk, sk = Sign.keypair () in
    let pk', sk' = Sign.keypair () in
    assert (Sign.Public_key.equal pk pk);
    assert (not (Sign.Public_key.equal pk pk'));
    assert Sign.Public_key.(length = Bytes.length @@ to_bytes pk);
    assert (Sign.Secret_key.equal sk sk);
    assert (not (Sign.Secret_key.equal sk sk'));
    assert Sign.Secret_key.(length = Bytes.length @@ to_bytes sk);
    let msg = "Hey ho!" in
    let plain_text = Bytes.of_string msg in
    let signed_text = Sign.sign ~secret_key:sk ~plain_text in
    let verify = Sign.open' ~public_key:pk ~signed_text in
    assert (verify = Some plain_text);
    assert (Sign.open' ~public_key:pk' ~signed_text = None);
    ()

  let test_secretbox () =
    log "Testing Secretbox";
    let sk = Secretbox.Secret_key.generate () in
    let sk' = Secretbox.Secret_key.generate () in
    let nonce = Secretbox.Nonce.generate () in
    assert (Secretbox.Secret_key.equal sk sk);
    assert (not (Secretbox.Secret_key.equal sk sk'));
    assert Secretbox.Secret_key.(length = Bytes.length @@ to_bytes sk);
    assert Secretbox.Nonce.(length = Bytes.length @@ to_bytes nonce);
    let plain_text = Bytes.of_string "Why is this so secret ?" in
    let cipher_text = Secretbox.box ~secret_key:sk ~nonce ~plain_text in
    let dec = Secretbox.open' ~secret_key:sk ~nonce ~cipher_text in
    let invalid_dec =
      Secretbox.open' ~secret_key:sk' ~nonce ~cipher_text
    in
    assert (not (equal_cbytes cipher_text plain_text));
    (match dec with
    | None -> assert false | Some p -> assert_cbytes p plain_text);
    (match invalid_dec with | None -> () | Some _ -> assert false);
    ()

  let test_stream () =
    log "Testing Stream";
    let sk0 = Stream.Secret_key.generate () in
    let sk1 = Stream.Secret_key.generate () in
    assert (Stream.Secret_key.equal sk0 sk0);
    assert (not (Stream.Secret_key.equal sk0 sk1));
    assert Stream.Secret_key.(length = Bytes.length @@ to_bytes sk0);
    let n0 = Stream.Nonce.generate () in
    let n1 = Stream.Nonce.generate () in
    assert (Stream.Nonce.equal n0 n0);
    assert (not (Stream.Nonce.equal n0 n1));
    assert Stream.Nonce.(length = Bytes.length @@ to_bytes n0);
    let msg = Bytes.of_string "Oh please encrypt me, pleeeeease!" in
    let xmsg = Stream.xor ~secret_key:sk0 ~nonce:n0 ~stream:msg in
    let xxmsg = Stream.xor ~secret_key:sk0 ~nonce:n0 ~stream:xmsg in
    assert (not (equal_cbytes msg xmsg));
    assert (equal_cbytes msg xxmsg);
    let xmsg' = Stream.xor ~secret_key:sk0 ~nonce:n1 ~stream:msg in
    let xxmsg' = Stream.xor ~secret_key:sk0 ~nonce:n1 ~stream:xmsg' in
    let xxmsg_bad_nonce = Stream.xor ~secret_key:sk0 ~nonce:n0 ~stream:xmsg' in
    assert (not (equal_cbytes msg xmsg'));
    assert (equal_cbytes msg xxmsg');
    assert (not (equal_cbytes msg xxmsg_bad_nonce));
    let length = Bytes.length msg in
    (* Do the same manually *)
    let rs = Stream.stream ~secret_key:sk0 ~nonce:n0 ~length in
    let xor b0 b1 i = (Bytes.get b0 i) lxor (Bytes.get b1 i) in
    let rs_xmsg = Bytes.init length ~init:(xor rs msg) in
    let rs_xxmsg = Bytes.init length ~init:(xor rs rs_xmsg) in
    assert (equal_cbytes rs_xmsg xmsg);
    assert (equal_cbytes msg rs_xxmsg);
    ()

  let test_onetimeauth () =
    log "Testing Onetimeauth";
    let k0 = Onetimeauth.Secret_key.generate () in
    let k1 = Onetimeauth.Secret_key.generate () in
    assert (Onetimeauth.Secret_key.equal k0 k0);
    assert (not (Onetimeauth.Secret_key.equal k0 k1));
    assert Onetimeauth.Secret_key.(length = Bytes.length @@ to_bytes k0);
    let msg = Bytes.of_string "Authenticate me! One more time!" in
    let msg' = Bytes.of_string "Never Authenticate me!" in
    let a0 = Onetimeauth.auth ~secret_key:k0 msg in
    let a1 = Onetimeauth.auth ~secret_key:k1 msg in
    assert (Onetimeauth.Authenticator.equal a0 a0);
    assert (not (Onetimeauth.Authenticator.equal a0 a1));
    assert Onetimeauth.Authenticator.(length = Bytes.length @@ to_bytes a0);
    assert      (Onetimeauth.verify ~secret_key:k0 ~auth:a0 msg);
    assert (not (Onetimeauth.verify ~secret_key:k0 ~auth:a1 msg));
    assert (not (Onetimeauth.verify ~secret_key:k0 ~auth:a0 msg'));
    assert (not (Onetimeauth.verify ~secret_key:k0 ~auth:a1 msg'));
    assert (not (Onetimeauth.verify ~secret_key:k1 ~auth:a0 msg));
    assert      (Onetimeauth.verify ~secret_key:k1 ~auth:a1 msg);
    assert (not (Onetimeauth.verify ~secret_key:k1 ~auth:a0 msg'));
    assert (not (Onetimeauth.verify ~secret_key:k1 ~auth:a1 msg'));
    ()

  let test_hash () =
    log "Testing Hash";
    let h = Hash.hash (Bytes.of_string "abc") in
    assert_int (Bytes.length (Hash.to_bytes h)) (Hash.length);
    assert_cbytes (Hash.to_bytes h)
      (Bytes.of_hex "ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 \
                     0a9eeee64b55d39a 2192992a274fc1a8 36ba3c23a3feebbd \
                     454d4423643ce80e 2a9ac94fa54ca49f" |> Result.get_ok);
    let h = Hash.hash (Bytes.of_string "") in
    assert_int (Bytes.length (Hash.to_bytes h)) (Hash.length);
    assert_cbytes (Hash.to_bytes h)
      (Bytes.of_hex "cf83e1357eefb8bd f1542850d66d8007 d620e4050b5715dc \
                     83f4a921d36ce9ce 47d0d13c5d85f2b0 ff8318d2877eec2f \
                     63b931bd47417a81 a538327af927da3e" |> Result.get_ok);
    ()

  let test_verify () =
    log "Testing Verify";
    let altered_copy b =
      let b' = Bytes.copy b in
      Bytes.set b' 0 ((1 + (Bytes.get b 0)) mod 256); b'
    in
    let r16 = Bytes.of_string (rstring 16) in
    let r16' = altered_copy r16 in
    let r32 = Bytes.of_string (rstring 32) in
    let r32' = altered_copy r32 in
    assert_invalid_arg (fun () -> Verify.bytes_16 r16 r32);
    assert_invalid_arg (fun () -> Verify.bytes_16 r32 r16);
    assert_bool (Verify.bytes_16 r16 r16) true;
    assert_bool (Verify.bytes_16 r16 r16') false;
    assert_bool (Verify.bytes_32 r32 r32) true;
    assert_bool (Verify.bytes_32 r32 r32') false;
    assert_invalid_arg (fun () -> Verify.bytes_32 r16 r32);
    assert_invalid_arg (fun () -> Verify.bytes_32 r32 r16);
    let r1024 = Bytes.of_string (rstring 1024) in
    let r1024' = altered_copy r1024 in
    let r33 = Bytes.of_string (rstring 33) in
    let r33' = altered_copy r33 in
    let empty = Bytes.of_string "" in
    assert_bool (Verify.bytes r1024 r1024) true;
    assert_bool (Verify.bytes r1024' r1024') true;
    assert_bool (Verify.bytes r1024 r1024') false;
    assert_bool (Verify.bytes r1024' r1024) false;
    assert_bool (Verify.bytes r33 r33) true;
    assert_bool (Verify.bytes r33' r33') true;
    assert_bool (Verify.bytes r33 r33') false;
    assert_bool (Verify.bytes r33' r33) false;
    assert_bool (Verify.bytes empty empty) true;
    ()

  let all () =
    test_to_of_string ();
    test_to_of_bytes ();
    test_to_of_bigbytes ();
    test_to_of_hex ();
    test_clear ();
    test_entropy ();
    test_box ();
    test_scalarmult ();
    test_sign ();
    test_secretbox ();
    test_stream ();
    test_onetimeauth ();
    test_hash ();
    test_verify ();
    Gc.full_major (); (* look for segfaults *)
    ()
end

module Bigcrypto_test = Test (Ttweetnacl.Bigcrypto)
module Crypto_test = Test (Ttweetnacl.Crypto)

let tests () =
  log "# Testing Bigcrypto";
  Bigcrypto_test.all ();
  log "\n# Testing Crypto";
  Crypto_test.all ();
  log "\nSuccess!"

let () = if !Sys.interactive then () else tests ()

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
