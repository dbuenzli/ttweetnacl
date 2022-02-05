/*---------------------------------------------------------------------------
   Copyright (c) 2022 The ttweetnacl programmers. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*/

#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/memory.h>
#include <caml/bigarray.h>
#include <caml/threads.h>
#include <caml/fail.h>

/* TweetNaCl needs an external randombytes() function for entropy.
   The platform specific dance here is just for defining one. */

#define OCAML_TTWEETNACL_RAISE_SYS_ERROR(ERR)                         \
  do { caml_raise_sys_error (caml_copy_string("Ttweetnacl: " ERR)); } \
  while (0)

/* Unix & Darwin, use getentropy() */

#if (defined(__unix__) || defined(__unix) || defined(__APPLE__)) && \
  !defined(__NetBSD__) /* Unsupported for now */

#if defined(__APPLE__)
#include <sys/random.h>
#else
#include <unistd.h>
#endif

void randombytes(unsigned char *b, unsigned long long blen)
{
  if (getentropy (b, blen) != 0)
  { OCAML_TTWEETNACL_RAISE_SYS_ERROR ("getentropy() failed"); }
}

/* Windows */

#elif defined(_WIN32)

#include <windows.h>

# define RtlGenRandom SystemFunction036
BOOLEAN NTAPI RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);
# pragma comment(lib, "advapi32.lib")

void randombytes(unsigned char *b, unsigned long long blen)
{
  if (!RtlGenRandom((PVOID)b, (ULONG)blen))
  { OCAML_TTWEETNACL_RAISE_SYS_ERROR ("RtlGenRandom() failed"); };
}

/* Unsupported */

#else

#warning OCaml Ttweetnacl: unsupported platform
void randombytes(unsigned char *b, unsigned long long blen)
{ OCAML_TTWEETNACL_RAISE_SYS_ERROR ("randombytes: unsupported platform"); }

#endif

/* randombytes() OCaml binding */

CAMLprim value ocaml_ttnacl_bigentropy_gather (value b)
{
  unsigned char *cb = (unsigned char *)(Caml_ba_data_val (b));
  long long len = caml_ba_byte_size (Caml_ba_array_val (b));
  caml_release_runtime_system ();
  randombytes (cb, len);
  caml_acquire_runtime_system ();
  return Val_unit;
}

CAMLprim value ocaml_ttnacl_entropy_gather (value b)
{
  randombytes (Bytes_val (b), caml_string_length (b));
  return Val_unit;
}

/* Tweetnacl Ocaml bindings */

#include "tweetnacl.h"

/* Box */

CAMLprim value ocaml_ttnacl_crypto_box_publickeybytes (value unit)
{ return Val_int (crypto_box_PUBLICKEYBYTES); }

CAMLprim value ocaml_ttnacl_crypto_box_secretkeybytes (value unit)
{ return Val_int (crypto_box_SECRETKEYBYTES); }

CAMLprim value ocaml_ttnacl_crypto_box_beforenmbytes (value unit)
{ return Val_int (crypto_box_BEFORENMBYTES); }

CAMLprim value ocaml_ttnacl_crypto_box_noncebytes (value unit)
{ return Val_int (crypto_box_NONCEBYTES); }

CAMLprim value ocaml_ttnacl_crypto_box_zerobytes (value unit)
{ return Val_int (crypto_box_ZEROBYTES); }

CAMLprim value ocaml_ttnacl_crypto_box_boxzerobytes (value unit)
{ return Val_int (crypto_box_BOXZEROBYTES); }

CAMLprim value ocaml_ttnacl_bigcrypto_box_keypair (value pk, value sk)
{
  unsigned char *cpk = (unsigned char *)(Caml_ba_data_val (pk));
  unsigned char *csk = (unsigned char *)(Caml_ba_data_val (sk));
  caml_release_runtime_system ();
  crypto_box_keypair (cpk, csk);
  caml_acquire_runtime_system ();
  return Val_unit;
}

CAMLprim value ocaml_ttnacl_bigcrypto_box
(value c, value m, value nonce, value pk, value sk)
{
  unsigned char *cc = (unsigned char *)(Caml_ba_data_val (c));
  unsigned char *cm = (unsigned char *)(Caml_ba_data_val (m));
  long long len = caml_ba_byte_size (Caml_ba_array_val (m));
  unsigned char *cnonce = (unsigned char *)(Caml_ba_data_val (nonce));
  unsigned char *cpk = (unsigned char *)(Caml_ba_data_val (pk));
  unsigned char *csk = (unsigned char *)(Caml_ba_data_val (sk));
  caml_release_runtime_system ();
  crypto_box (cc, cm, len, cnonce, cpk, csk);
  caml_acquire_runtime_system ();
  return Val_unit;
}

CAMLprim value ocaml_ttnacl_bigcrypto_box_open
(value m, value c, value nonce, value pk, value sk)
{
  unsigned char *cm = (unsigned char *)(Caml_ba_data_val (m));
  unsigned char *cc = (unsigned char *)(Caml_ba_data_val (c));
  long long len = caml_ba_byte_size (Caml_ba_array_val (c));
  unsigned char *cnonce = (unsigned char *)(Caml_ba_data_val (nonce));
  unsigned char *cpk = (unsigned char *)(Caml_ba_data_val (pk));
  unsigned char *csk = (unsigned char *)(Caml_ba_data_val (sk));
  int ret = -1;
  caml_release_runtime_system ();
  ret = crypto_box_open (cm, cc, len, cnonce, cpk, csk);
  caml_acquire_runtime_system ();
  return Val_bool (!ret);
}
CAMLprim value ocaml_ttnacl_bigcrypto_box_before (value ssk, value pk, value sk)
{
  unsigned char *cssk = (unsigned char *)(Caml_ba_data_val (ssk));
  unsigned char *cpk = (unsigned char *)(Caml_ba_data_val (pk));
  unsigned char *csk = (unsigned char *)(Caml_ba_data_val (sk));
  crypto_box_beforenm (cssk, cpk, csk);
  return Val_unit;
}

CAMLprim value ocaml_ttnacl_bigcrypto_box_after
(value c, value m, value nonce, value ssk)
{
  unsigned char *cc = (unsigned char *)(Caml_ba_data_val (c));
  unsigned char *cm = (unsigned char *)(Caml_ba_data_val (m));
  long long len = caml_ba_byte_size (Caml_ba_array_val (m));
  unsigned char *cnonce = (unsigned char *)(Caml_ba_data_val (nonce));
  unsigned char *cssk = (unsigned char *)(Caml_ba_data_val (ssk));
  caml_release_runtime_system ();
  crypto_box_afternm (cc, cm, len, cnonce, cssk);
  caml_acquire_runtime_system ();
  return Val_unit;
}

CAMLprim value ocaml_ttnacl_bigcrypto_box_open_after
(value m, value c, value nonce, value ssk)
{
  unsigned char *cm = (unsigned char *)(Caml_ba_data_val (m));
  unsigned char *cc = (unsigned char *)(Caml_ba_data_val (c));
  long long len = caml_ba_byte_size (Caml_ba_array_val (c));
  unsigned char *cnonce = (unsigned char *)(Caml_ba_data_val (nonce));
  unsigned char *cssk = (unsigned char *)(Caml_ba_data_val (ssk));
  int ret = -1;
  caml_release_runtime_system ();
  ret = crypto_box_open_afternm (cm, cc, len, cnonce, cssk);
  caml_acquire_runtime_system ();
  return Val_bool (!ret);
}

CAMLprim value ocaml_ttnacl_crypto_box_keypair (value pk, value sk)
{
  crypto_box_keypair (Bytes_val (pk), Bytes_val (sk));
  return Val_unit;
}

CAMLprim value ocaml_ttnacl_crypto_box
(value c, value m, value nonce, value pk, value sk)
{
  crypto_box (Bytes_val (c), Bytes_val (m), caml_string_length (m),
              Bytes_val (nonce), Bytes_val (pk), Bytes_val (sk));
  return Val_unit;
}

CAMLprim value ocaml_ttnacl_crypto_box_open
(value m, value c, value nonce, value pk, value sk)
{
  return Val_bool (!crypto_box_open (Bytes_val (m), Bytes_val (c),
                                     caml_string_length (c), Bytes_val (nonce),
                                     Bytes_val (pk), Bytes_val (sk)));
}

CAMLprim value ocaml_ttnacl_crypto_box_before (value ssk, value pk, value sk)
{
  crypto_box_beforenm (Bytes_val (ssk), Bytes_val (pk), Bytes_val (sk));
  return Val_unit;
}

CAMLprim value ocaml_ttnacl_crypto_box_after
(value c, value m, value nonce, value ssk)
{
  crypto_box_afternm (Bytes_val (c), Bytes_val (m), caml_string_length (m),
                      Bytes_val (nonce), Bytes_val (ssk));
  return Val_unit;
}

CAMLprim value ocaml_ttnacl_crypto_box_open_after
(value m, value c, value nonce, value ssk)
{
  return Val_bool (!crypto_box_open_afternm (Bytes_val (m), Bytes_val (c),
                                             caml_string_length (c),
                                             Bytes_val (nonce),
                                             Bytes_val (ssk)));
}

/* Scalarmult */

CAMLprim value ocaml_ttnacl_crypto_scalarmult_scalarbytes (value unit)
{ return Val_int (crypto_scalarmult_SCALARBYTES); }

CAMLprim value ocaml_ttnacl_crypto_scalarmult_bytes (value unit)
{ return Val_int (crypto_scalarmult_BYTES); }

CAMLprim value ocaml_ttnacl_bigcrypto_scalarmult (value q, value n, value p)
{
  unsigned char *cq = (unsigned char *)(Caml_ba_data_val (q));
  unsigned char *cn = (unsigned char *)(Caml_ba_data_val (n));
  unsigned char *cp = (unsigned char *)(Caml_ba_data_val (p));

  caml_release_runtime_system ();
  crypto_scalarmult (cq, cn, cp);
  caml_acquire_runtime_system ();
  return Val_unit;
}

CAMLprim value ocaml_ttnacl_bigcrypto_scalarmult_base (value q, value n)
{
  unsigned char *cq = (unsigned char *)(Caml_ba_data_val (q));
  unsigned char *cn = (unsigned char *)(Caml_ba_data_val (n));

  caml_release_runtime_system ();
  crypto_scalarmult_base (cq, cn);
  caml_acquire_runtime_system ();
  return Val_unit;
}

CAMLprim value ocaml_ttnacl_crypto_scalarmult (value q, value n, value p)
{
  crypto_scalarmult (Bytes_val (q), Bytes_val (n), Bytes_val (p));
  return Val_unit;
}

CAMLprim value ocaml_ttnacl_crypto_scalarmult_base (value q, value n)
{
  crypto_scalarmult_base (Bytes_val (q), Bytes_val (n));
  return Val_unit;
}

/* Sign */

CAMLprim value ocaml_ttnacl_crypto_sign_publickeybytes (value unit)
{ return Val_int (crypto_sign_PUBLICKEYBYTES); }

CAMLprim value ocaml_ttnacl_crypto_sign_secretkeybytes (value unit)
{ return Val_int (crypto_sign_SECRETKEYBYTES); }

CAMLprim value ocaml_ttnacl_crypto_sign_bytes (value unit)
{ return Val_int (crypto_sign_BYTES); }

CAMLprim value ocaml_ttnacl_bigcrypto_sign_keypair (value pk, value sk)
{
  unsigned char *cpk = (unsigned char *)(Caml_ba_data_val (pk));
  unsigned char *csk = (unsigned char *)(Caml_ba_data_val (sk));
  caml_release_runtime_system ();
  crypto_sign_keypair (cpk, csk);
  caml_acquire_runtime_system ();
  return Val_unit;
}

CAMLprim value ocaml_ttnacl_bigcrypto_sign (value sm, value m, value sk)
{
  unsigned char *csm = (unsigned char *)(Caml_ba_data_val (sm));
  unsigned char *cm = (unsigned char *)(Caml_ba_data_val (m));
  unsigned char *csk = (unsigned char *)(Caml_ba_data_val (sk));
  unsigned long long mlen = caml_ba_byte_size (Caml_ba_array_val (m));
  unsigned long long smlen = 0;
  caml_release_runtime_system ();
  crypto_sign (csm, &smlen, cm, mlen, csk);
  caml_acquire_runtime_system ();
  return Val_int (smlen);
}

CAMLprim value ocaml_ttnacl_bigcrypto_sign_open (value m, value sm, value pk)
{
  unsigned char *cm = (unsigned char *)(Caml_ba_data_val (m));
  unsigned char *csm = (unsigned char *)(Caml_ba_data_val (sm));
  unsigned char *cpk = (unsigned char *)(Caml_ba_data_val (pk));
  unsigned long long smlen = caml_ba_byte_size (Caml_ba_array_val (sm));
  unsigned long long mlen = 0;
  int ret = -1;
  caml_release_runtime_system ();
  ret = crypto_sign_open (cm, &mlen, csm, smlen, cpk);
  caml_acquire_runtime_system ();
  return Val_int ((ret < 0) ? -1 : mlen);
}

CAMLprim value ocaml_ttnacl_crypto_sign_keypair (value pk, value sk)
{
  crypto_sign_keypair (Bytes_val (pk), Bytes_val (sk));
  return Val_unit;
}

CAMLprim value ocaml_ttnacl_crypto_sign (value sm, value m, value sk)
{
  unsigned long long smlen = 0;
  crypto_sign (Bytes_val (sm), &smlen, Bytes_val (m), caml_string_length (m),
               Bytes_val (sk));
  return Val_int (smlen);
}

CAMLprim value ocaml_ttnacl_crypto_sign_open (value m, value sm, value pk)
{
  unsigned long long mlen = 0;
  int ret = -1;
  ret = crypto_sign_open (Bytes_val (m), &mlen, Bytes_val (sm),
                          caml_string_length (sm), Bytes_val (pk));
  return Val_int ((ret < 0) ? -1 : mlen);
}

/* Secretbox */

CAMLprim value ocaml_ttnacl_crypto_secretbox_keybytes (value unit)
{ return Val_int (crypto_secretbox_KEYBYTES); }

CAMLprim value ocaml_ttnacl_crypto_secretbox_noncebytes (value unit)
{ return Val_int (crypto_secretbox_NONCEBYTES); }

CAMLprim value ocaml_ttnacl_crypto_secretbox_zerobytes (value unit)
{ return Val_int (crypto_secretbox_ZEROBYTES); }

CAMLprim value ocaml_ttnacl_crypto_secretbox_boxzerobytes (value unit)
{ return Val_int (crypto_secretbox_BOXZEROBYTES); }

CAMLprim value ocaml_ttnacl_bigcrypto_secretbox
(value c, value m, value nonce, value k)
{
  unsigned char *cc = (unsigned char *)(Caml_ba_data_val (c));
  unsigned char *cm = (unsigned char *)(Caml_ba_data_val (m));
  long long len = caml_ba_byte_size (Caml_ba_array_val (m));
  unsigned char *cnonce = (unsigned char *)(Caml_ba_data_val (nonce));
  unsigned char *ck = (unsigned char *)(Caml_ba_data_val (k));

  caml_release_runtime_system ();
  crypto_secretbox (cc, cm, len, cnonce, ck);
  caml_acquire_runtime_system ();
  return Val_unit;
}

CAMLprim value ocaml_ttnacl_bigcrypto_secretbox_open
(value m, value c, value nonce, value k)
{
  unsigned char *cm = (unsigned char *)(Caml_ba_data_val (m));
  unsigned char *cc = (unsigned char *)(Caml_ba_data_val (c));
  long long len = caml_ba_byte_size (Caml_ba_array_val (c));
  unsigned char *cnonce = (unsigned char *)(Caml_ba_data_val (nonce));
  unsigned char *ck = (unsigned char *)(Caml_ba_data_val (k));
  int ret = -1;

  caml_release_runtime_system ();
  ret = crypto_secretbox_open (cm, cc, len, cnonce, ck);
  caml_acquire_runtime_system ();
  return Val_bool (!ret);
}

CAMLprim value ocaml_ttnacl_crypto_secretbox
(value c, value m, value nonce, value k)
{
  crypto_secretbox (Bytes_val (c), Bytes_val (m), caml_string_length (m),
                    Bytes_val (nonce), Bytes_val (k));
  return Val_unit;
}

CAMLprim value ocaml_ttnacl_crypto_secretbox_open
(value m, value c, value nonce, value k)
{
  return Val_bool (!crypto_secretbox_open (Bytes_val (m), Bytes_val (c),
                                           caml_string_length (c),
                                           Bytes_val (nonce), Bytes_val (k)));
}

/* Stream */

CAMLprim value ocaml_ttnacl_crypto_stream_keybytes (value unit)
{ return Val_int (crypto_stream_KEYBYTES); }

CAMLprim value ocaml_ttnacl_crypto_stream_noncebytes (value unit)
{ return Val_int (crypto_stream_NONCEBYTES); }

CAMLprim value ocaml_ttnacl_bigcrypto_stream (value c, value n, value k)
{
  unsigned char *cc = (unsigned char *)(Caml_ba_data_val (c));
  unsigned char *cn = (unsigned char *)(Caml_ba_data_val (n));
  unsigned char *ck = (unsigned char *)(Caml_ba_data_val (k));
  long long len = caml_ba_byte_size (Caml_ba_array_val (c));
  caml_release_runtime_system ();
  crypto_stream (cc, len, cn, ck);
  caml_acquire_runtime_system ();
  return Val_unit;
}

CAMLprim value ocaml_ttnacl_bigcrypto_stream_xor
(value c, value m, value n, value k)
{
  unsigned char *cc = (unsigned char *)(Caml_ba_data_val (c));
  unsigned char *cm = (unsigned char *)(Caml_ba_data_val (m));
  unsigned char *cn = (unsigned char *)(Caml_ba_data_val (n));
  unsigned char *ck = (unsigned char *)(Caml_ba_data_val (k));
  long long len = caml_ba_byte_size (Caml_ba_array_val (m));
  caml_release_runtime_system ();
  crypto_stream_xor (cc, cm, len, cn, ck);
  caml_acquire_runtime_system ();
  return Val_unit;
}

CAMLprim value ocaml_ttnacl_crypto_stream (value c, value n, value k)
{
  crypto_stream (Bytes_val (c), caml_string_length (c), Bytes_val (n),
                 Bytes_val (k));
  return Val_unit;
}

CAMLprim value ocaml_ttnacl_crypto_stream_xor
(value c, value m, value n, value k)
{
  crypto_stream_xor (Bytes_val (c), Bytes_val (m), caml_string_length (m),
                     Bytes_val (n), Bytes_val (k));
  return Val_unit;
}

/* Onetimeauth */

CAMLprim value ocaml_ttnacl_crypto_onetimeauth_keybytes (value unit)
{ return Val_int (crypto_onetimeauth_KEYBYTES); }

CAMLprim value ocaml_ttnacl_crypto_onetimeauth_bytes (value unit)
{ return Val_int (crypto_onetimeauth_BYTES); }

CAMLprim value ocaml_ttnacl_bigcrypto_onetimeauth (value a, value m, value k)
{
  unsigned char *ca = (unsigned char *)(Caml_ba_data_val (a));
  unsigned char *cm = (unsigned char *)(Caml_ba_data_val (m));
  unsigned char *ck = (unsigned char *)(Caml_ba_data_val (k));
  long long len = caml_ba_byte_size (Caml_ba_array_val (m));
  caml_release_runtime_system ();
  crypto_onetimeauth (ca, cm, len, ck);
  caml_acquire_runtime_system ();
  return Val_unit;
}

CAMLprim value ocaml_ttnacl_bigcrypto_onetimeauth_verify
(value a, value m, value k)
{
  unsigned char *ca = (unsigned char *)(Caml_ba_data_val (a));
  unsigned char *cm = (unsigned char *)(Caml_ba_data_val (m));
  unsigned char *ck = (unsigned char *)(Caml_ba_data_val (k));
  long long len = caml_ba_byte_size (Caml_ba_array_val (m));
  int ret = -1;
  caml_release_runtime_system ();
  ret = crypto_onetimeauth_verify (ca, cm, len, ck);
  caml_acquire_runtime_system ();
  return Val_bool (!ret);
}

CAMLprim value ocaml_ttnacl_crypto_onetimeauth (value a, value m, value k)
{
  crypto_onetimeauth (Bytes_val (a), Bytes_val (m), caml_string_length (m),
                      Bytes_val (k));
  return Val_unit;
}

CAMLprim value ocaml_ttnacl_crypto_onetimeauth_verify
(value a, value m, value k)
{
  return Val_bool (!crypto_onetimeauth_verify (Bytes_val (a), Bytes_val (m),
                                               caml_string_length (m),
                                               Bytes_val (k)));
}

/* Hash */

CAMLprim value ocaml_ttnacl_crypto_hash_bytes (value unit)
{ return Val_int (crypto_hash_BYTES); }

CAMLprim value ocaml_ttnacl_bigcrypto_hash (value h, value m)
{
  unsigned char *ch = (unsigned char *)(Caml_ba_data_val (h));
  unsigned char *cm = (unsigned char *)(Caml_ba_data_val (m));
  long long len = caml_ba_byte_size (Caml_ba_array_val (m));

  caml_release_runtime_system ();
  crypto_hash (ch, cm, len);
  caml_acquire_runtime_system ();
  return Val_unit;
}

CAMLprim value ocaml_ttnacl_crypto_hash (value h, value m)
{
  crypto_hash (Bytes_val (h), Bytes_val (m), caml_string_length (m));
  return Val_unit;
}

/* Verify, these funs return 0 on equal and -1 otherwise, hence the negation. */

CAMLprim value ocaml_ttnacl_bigcrypto_verify_16 (value b0, value b1)
{
  return Val_bool (!crypto_verify_16 (Caml_ba_data_val (b0),
                                      Caml_ba_data_val (b1)));
}

CAMLprim value ocaml_ttnacl_bigcrypto_verify_32 (value b0, value b1)
{
  return Val_bool (!crypto_verify_32 (Caml_ba_data_val (b0),
                                      Caml_ba_data_val (b1)));
}

CAMLprim value ocaml_ttnacl_crypto_verify_16 (value b0, value b1)
{
  return Val_bool (!crypto_verify_16 (Bytes_val (b0), Bytes_val (b1)));
}

CAMLprim value ocaml_ttnacl_crypto_verify_32 (value b0, value b1)
{
  return Val_bool (!crypto_verify_32 (Bytes_val (b0), Bytes_val (b1)));
}

/* Except for size_t args this is a copy from tweetnacl.c vn() function. */
static int verify_n(const unsigned char *x, const unsigned char *y, size_t n)
{
  size_t i = 0;
  unsigned long d = 0;
  for (i = 0 ; i < n; ++i) d |= x[i]^y[i];
  return (1 & ((d - 1) >> 8)) - 1;
}

CAMLprim value ocaml_ttnacl_bigcrypto_verify_n (value b0, value b1)
{
  unsigned char *cb0 = (unsigned char *)(Caml_ba_data_val (b0));
  unsigned char *cb1 = (unsigned char *)(Caml_ba_data_val (b1));
  size_t len = caml_ba_byte_size (Caml_ba_array_val (b0));

  return Val_bool (!verify_n (cb0, cb1, len));
}

CAMLprim value ocaml_ttnacl_crypto_verify_n (value b0, value b1)
{
  return Val_bool (!verify_n (Bytes_val (b0), Bytes_val (b1),
                              caml_string_length (b0)));
}

/*---------------------------------------------------------------------------
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
  ---------------------------------------------------------------------------*/
