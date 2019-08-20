open Core

val random_buffer : int -> bytes
val zero_buffer : bytes -> unit
val copy_buffer : src:bytes -> dst:bytes -> unit Or_error.t
val equals : bytes -> bytes -> bool
val is_zero : bytes -> bool

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

  val generate_key : len:int -> key
end

module Public : sig
  include Key_utils
end

type keypair = {secret: Secret.key; public: Public.key} [@@deriving sexp_of]

val copy_keypair : src:keypair -> dst:keypair -> unit Or_error.t
val zero_keypair : keypair -> unit
