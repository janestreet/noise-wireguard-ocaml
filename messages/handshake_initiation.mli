type t =
  { msg_type: Cstruct.uint32
  ; sender: Cstruct.uint32
  ; ephemeral: bytes
  ; signed_static: bytes
  ; signed_timestamp: bytes
  ; mac1: bytes ref
  ; mac2: bytes ref
  ; msg_alpha: Cstruct.t
  ; msg_beta: Cstruct.t }

type t_cstruct

val t_to_cstruct : t -> t_cstruct
val cstruct_to_t : t_cstruct -> t
val hexdump_t_cstruct : t_cstruct -> unit
val set_macs : msg:t_cstruct -> mac1:bytes -> mac2:bytes -> unit

val create_t_cstruct :
     sender:int32
  -> ephemeral:bytes
  -> signed_static:bytes
  -> signed_timestamp:bytes
  -> t_cstruct
