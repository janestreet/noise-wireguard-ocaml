open Core
open Stdint

let poly1305_tag_size = 16

type data_with_len = {bytes: bytes; mutable len: int64}

let add_len bytes = {bytes; len= Bytes.length bytes |> Int.to_int64}
let aead_nonce_length = 12 (* bytes *)

let xaead_nonce_length = 24 (* bytes *)

external aead_encrypt_ :
     data_with_len (* dst ciphertext *)
  -> data_with_len (* src message *)
  -> data_with_len (* src auth_text *)
  -> Bytes.t (* nonce *)
  -> Bytes.t (* key *)
  -> int = "caml_crypto_aead_chacha20poly1305_encrypt"

external aead_decrypt_ :
     data_with_len (* dst message *)
  -> data_with_len (* src ciphertext *)
  -> data_with_len (* src auth_text *)
  -> Bytes.t (* nonce *)
  -> Bytes.t (* key *)
  -> int = "caml_crypto_aead_chacha20poly1305_decrypt"

external xaead_encrypt_ :
     data_with_len (* dst ciphertext *)
  -> data_with_len (* src message *)
  -> data_with_len (* src auth_text *)
  -> Bytes.t (* nonce *)
  -> Bytes.t (* key *)
  -> int = "caml_crypto_xaead_xchacha20poly1305_encrypt"

external xaead_decrypt_ :
     data_with_len (* dst message *)
  -> data_with_len (* src ciphertext *)
  -> data_with_len (* src auth_text *)
  -> Bytes.t (* nonce *)
  -> Bytes.t (* key *)
  -> int = "caml_crypto_xaead_xchacha20poly1305_decrypt"

let crypto_aead_chacha20poly1305_ABYTES = 16

let nonce_from_counter counter =
  let buf = Bytes.make aead_nonce_length '\x00' in
  Uint64.to_bytes_little_endian (Uint64.of_int64 counter) buf 4 ;
  buf

let aead_encrypt ~key ~counter ~message ~auth_text =
  let key = Key.Shared.to_bytes key in
  let nonce = nonce_from_counter counter in
  let m_with_len = add_len message in
  let c_with_len =
    let c_buf =
      Bytes.create
        ( (m_with_len.len |> Int.of_int64_exn)
        + crypto_aead_chacha20poly1305_ABYTES ) in
    add_len c_buf in
  let auth_with_len = add_len auth_text in
  let status = aead_encrypt_ c_with_len m_with_len auth_with_len nonce key in
  if status < 0 then
    Or_error.error_s [%message "failed to encrypt w/ aead" (status : int)]
  else Or_error.return c_with_len.bytes

let aead_decrypt ~key ~counter ~ciphertext ~auth_text =
  let key = Key.Shared.to_bytes key in
  let nonce = nonce_from_counter counter in
  let c_with_len = add_len ciphertext in
  let m_with_len =
    let m_buf =
      Bytes.create
        ( (c_with_len.len |> Int.of_int64_exn)
        - crypto_aead_chacha20poly1305_ABYTES ) in
    add_len m_buf in
  let auth_with_len = add_len auth_text in
  let status = aead_decrypt_ m_with_len c_with_len auth_with_len nonce key in
  if status < 0 then
    Or_error.error_s [%message "failed to decrypt w/ aead" (status : int)]
  else Or_error.return m_with_len.bytes

let xaead_encrypt ~key ~nonce ~message ~auth_text =
  let key = Key.Shared.to_bytes key in
  let m_with_len = add_len message in
  let c_with_len =
    let c_buf =
      Bytes.create
        ( (m_with_len.len |> Int.of_int64_exn)
        + crypto_aead_chacha20poly1305_ABYTES ) in
    add_len c_buf in
  let auth_with_len = add_len auth_text in
  let status = xaead_encrypt_ c_with_len m_with_len auth_with_len nonce key in
  if status < 0 then
    Or_error.error_s [%message "failed to encrypt w/ xaead" (status : int)]
  else Or_error.return c_with_len.bytes

let xaead_decrypt ~key ~nonce ~ciphertext ~auth_text =
  let key = Key.Shared.to_bytes key in
  let c_with_len = add_len ciphertext in
  let m_with_len =
    let m_buf =
      Bytes.create
        ( (c_with_len.len |> Int.of_int64_exn)
        - crypto_aead_chacha20poly1305_ABYTES ) in
    add_len m_buf in
  let auth_with_len = add_len auth_text in
  let status = xaead_decrypt_ m_with_len c_with_len auth_with_len nonce key in
  if status < 0 then
    Or_error.error_s [%message "failed to decrypt w/ xaead" (status : int)]
  else Or_error.return m_with_len.bytes

let%expect_test "test-aead-encrypt-decrypt" =
  Initialize.init () |> Or_error.ok_exn ;
  let message = Bytes.of_string "test" in
  let auth_text = Bytes.of_string "123456" in
  let key = Key.random_buffer 32 |> Key.Shared.of_bytes in
  let counter = Int.to_int64 50000 in
  let ciphertext =
    aead_encrypt ~key ~counter ~message ~auth_text |> Or_error.ok_exn in
  let thing =
    aead_decrypt ~key ~counter ~ciphertext ~auth_text |> Or_error.ok_exn in
  print_string (Bytes.to_string thing) ;
  [%expect {| test |}]

let%expect_test "test-xaead-encrypt-decrypt" =
  Initialize.init () |> Or_error.ok_exn ;
  let message = Bytes.of_string "test" in
  let auth_text = Bytes.of_string "123456" in
  let key = Key.random_buffer 32 |> Key.Shared.of_bytes in
  let nonce = Key.random_buffer xaead_nonce_length in
  let ciphertext =
    xaead_encrypt ~key ~nonce ~message ~auth_text |> Or_error.ok_exn in
  let thing =
    xaead_decrypt ~key ~nonce ~ciphertext ~auth_text |> Or_error.ok_exn in
  print_string (Bytes.to_string thing) ;
  [%expect {| test |}]
