open Core

type t

val init : Crypto.Public.key -> t Or_error.t

val consume_reply :
  t:t -> msg:Messages.Cookie_reply.t_cstruct -> unit Core.Or_error.t

val add_macs : t:t -> msg:Messages.mac_message -> unit Core.Or_error.t
