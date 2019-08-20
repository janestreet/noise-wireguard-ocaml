open Core

val init : unit -> unit Or_error.t
val random_buffer : int -> bytes
val zero_buffer : bytes -> unit
val copy_buffer : src:bytes -> dst:bytes -> unit Or_error.t
val equals : bytes -> bytes -> bool
val is_zero : bytes -> bool

(* TODO: add assertions about things being the right lengths everywhere *)
module type Key_utils = sig
  type key [@@deriving sexp_of]

  val to_hex : key -> string
  val of_hex : ?len:int -> string -> key Or_error.t
  val set_zero : key -> unit
  val of_bytes : bytes -> key
  val to_bytes : key -> bytes
  val copy_from_bytes : key -> bytes -> unit Or_error.t
  val copy_to_bytes : key -> bytes -> unit Or_error.t
  val copy : src:key -> dst:key -> unit Or_error.t
  val equals : key -> key -> bool
  val is_zero : key -> bool
  val clone : key -> key
  val create_uninit : unit -> key
end

module Shared : sig
  include Key_utils
end

module Secret : sig
  include Key_utils
end

module Public : sig
  include Key_utils
end

type keypair = {secret: Secret.key; public: Public.key} [@@deriving sexp_of]

val copy_keypair : src:keypair -> dst:keypair -> unit Or_error.t
val zero_keypair : keypair -> unit
val generate : unit -> keypair Or_error.t
val dh : public:Public.key -> secret:Secret.key -> Shared.key Or_error.t
val kdf_1 : key:Shared.key -> bytes -> Shared.key
val kdf_2 : key:Shared.key -> bytes -> Shared.key * Shared.key
val kdf_3 : key:Shared.key -> bytes -> Shared.key * Shared.key * Shared.key
val hash : bytes -> bytes Or_error.t
val hash2 : bytes -> bytes -> bytes Or_error.t
val mac : input:bytes -> key:Shared.key -> bytes Or_error.t
val hmac : input:bytes -> key:Shared.key -> bytes

val aead_encrypt :
     key:Shared.key
  -> counter:int64
  -> message:bytes
  -> auth_text:bytes
  -> bytes Or_error.t

val aead_decrypt :
     key:Shared.key
  -> counter:int64
  -> ciphertext:bytes
  -> auth_text:bytes
  -> bytes Or_error.t

val xaead_encrypt :
     key:Shared.key
  -> nonce:bytes
  -> message:bytes
  -> auth_text:bytes
  -> bytes Or_error.t

val xaead_decrypt :
     key:Shared.key
  -> nonce:bytes
  -> ciphertext:bytes
  -> auth_text:bytes
  -> bytes Or_error.t

val poly1305_tag_size : int
