open Core
open Key

val poly1305_tag_size : int

val aead_encrypt :
     key:Shared.key
  -> counter:int64
  -> message:Bytes.t
  -> auth_text:Bytes.t
  -> Bytes.t Or_error.t

val aead_decrypt :
     key:Shared.key
  -> counter:int64
  -> ciphertext:Bytes.t
  -> auth_text:Bytes.t
  -> Bytes.t Or_error.t

val xaead_encrypt :
     key:Shared.key
  -> nonce:Bytes.t
  -> message:Bytes.t
  -> auth_text:Bytes.t
  -> Bytes.t Or_error.t

val xaead_decrypt :
     key:Shared.key
  -> nonce:Bytes.t
  -> ciphertext:Bytes.t
  -> auth_text:Bytes.t
  -> Bytes.t Or_error.t
