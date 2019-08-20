type t

val init : Crypto.Public.key -> t Core.Or_error.t

val check_macs :
     ?should_check_mac2:bool
  -> t:t
  -> msg:Messages.mac_message
  -> src:bytes
  -> unit Core.Or_error.t

val create_reply :
     t:t
  -> msg:Messages.mac_message
  -> receiver:int32
  -> src:bytes
  -> Messages.Cookie_reply.t_cstruct Core.Or_error.t
