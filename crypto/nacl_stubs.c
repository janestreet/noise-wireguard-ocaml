#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/custom.h>
#include <caml/bigarray.h>
#include <caml/fail.h>
#include <caml/threads.h>

#include <sodium.h>
#include <blake2.h>

#if __GNUC__ >= 3
# define inline inline __attribute__ ((always_inline))
# if !defined(__FreeBSD__) && !__APPLE__
# define __unused __attribute__ ((unused))
# endif
#else
# define __unused
# define inline
#endif

CAMLprim value caml_sodium_init(value __unused v_unit) {
  CAMLparam0();
  CAMLreturn(Val_int(sodium_init()));
}

void caml_crypto_gen_key(value key_buf, value key_len) {
  randombytes_buf(Bytes_val(key_buf), Int_val(key_len));
}

CAMLprim value caml_crypto_gen_keypair(value pk, value sk) {
  CAMLparam2 (pk, sk);
  CAMLreturn(Val_int(crypto_kx_keypair(Bytes_val(pk), Bytes_val(sk))));
}

CAMLprim value caml_crypto_dh(value shared_buf, value sk, value pk) {
  CAMLparam3 (pk, sk, shared_buf);
  CAMLreturn(
    Val_int(
      crypto_scalarmult(Bytes_val(shared_buf), Bytes_val(sk), Bytes_val(pk))));
}

CAMLprim value caml_crypto_aead_chacha20poly1305_encrypt
  (value dst_ciphertext,
   value src_message,
   value src_auth_text,
   value nonce,
   value key) {
  CAMLparam5 (dst_ciphertext, src_message, src_auth_text, nonce, key);
  CAMLlocal1(myclen_p);
  unsigned long long clen_p;
  int ret_val = crypto_aead_chacha20poly1305_ietf_encrypt
                     (Bytes_val(Field(dst_ciphertext, 0)),
                      &clen_p,
                      Bytes_val(Field(src_message, 0)),
                      Int64_val(Field(src_message, 1)),
                      Bytes_val(Field(src_auth_text, 0)),
                      Int64_val(Field(src_auth_text, 1)),
                      NULL,
                      Bytes_val(nonce),
                      Bytes_val(key));
  myclen_p = caml_copy_int64(clen_p);
  Store_field(dst_ciphertext, 1, myclen_p);
  CAMLreturn(Val_int(ret_val));
}
CAMLprim value caml_crypto_aead_chacha20poly1305_decrypt
  (value dst_message,
   value src_ciphertext,
   value src_auth_text,
   value nonce,
   value key) {

  CAMLparam5 (dst_message, src_ciphertext, src_auth_text, nonce, key);
  CAMLlocal1(myclen_p);
  unsigned long long clen_p;
  int ret_val = crypto_aead_chacha20poly1305_ietf_decrypt
                     (Bytes_val(Field(dst_message, 0)),
                      &clen_p,
                      NULL,
                      Bytes_val(Field(src_ciphertext, 0)),
                      Int64_val(Field(src_ciphertext, 1)),
                      Bytes_val(Field(src_auth_text, 0)),
                      Int64_val(Field(src_auth_text, 1)),
                      Bytes_val(nonce),
                      Bytes_val(key));
  myclen_p = caml_copy_int64(clen_p);
  Store_field(dst_message, 1, myclen_p);
  CAMLreturn(Val_int(ret_val));
}
CAMLprim value caml_crypto_xaead_xchacha20poly1305_encrypt
  (value dst_ciphertext,
   value src_message,
   value src_auth_text,
   value nonce,
   value key) {
     CAMLparam5 (dst_ciphertext, src_message, src_auth_text, nonce, key);
     CAMLlocal1(myclen_p);
     unsigned long long clen_p;
     int ret_val = crypto_aead_xchacha20poly1305_ietf_encrypt
                        (Bytes_val(Field(dst_ciphertext, 0)),
                         &clen_p,
                         Bytes_val(Field(src_message, 0)),
                         Int64_val(Field(src_message, 1)),
                         Bytes_val(Field(src_auth_text, 0)),
                         Int64_val(Field(src_auth_text, 1)),
                         NULL,
                         Bytes_val(nonce),
                         Bytes_val(key));
     myclen_p = caml_copy_int64(clen_p);
     Store_field(dst_ciphertext, 1, myclen_p);
     CAMLreturn(Val_int(ret_val));

}
CAMLprim value caml_crypto_xaead_xchacha20poly1305_decrypt
  (value dst_message,
   value src_ciphertext,
   value src_auth_text,
   value nonce,
   value key) {

  CAMLparam5 (dst_message, src_ciphertext, src_auth_text, nonce, key);
  CAMLlocal1(myclen_p);
  unsigned long long clen_p;
  int ret_val = crypto_aead_xchacha20poly1305_ietf_decrypt
                     (Bytes_val(Field(dst_message, 0)),
                      &clen_p,
                      NULL,
                      Bytes_val(Field(src_ciphertext, 0)),
                      Int64_val(Field(src_ciphertext, 1)),
                      Bytes_val(Field(src_auth_text, 0)),
                      Int64_val(Field(src_auth_text, 1)),
                      Bytes_val(nonce),
                      Bytes_val(key));
  myclen_p = caml_copy_int64(clen_p);
  Store_field(dst_message, 1, myclen_p);
  CAMLreturn(Val_int(ret_val));
}

CAMLprim value caml_crypto_hash_blake2s(value input, value input_len, value out_buf) {

  CAMLparam3 (input, input_len, out_buf);

  CAMLreturn(Val_int(
                     blake2s(
                             Bytes_val(out_buf),
                             Bytes_val(input),
                             NULL,
                             32,
                             Int_val(input_len),
                             0)));
}

CAMLprim value caml_crypto_hash_keyed_blake2s(value input, value input_len, value key, value key_len, value out_buf) {

  CAMLparam5 (input, input_len, key, key_len, out_buf);

  CAMLreturn(Val_int(
    blake2s(
      Bytes_val(out_buf),
      Bytes_val(input),
      Bytes_val(key),
      16,
      Int_val(input_len),
      Int_val(key_len))));
}
