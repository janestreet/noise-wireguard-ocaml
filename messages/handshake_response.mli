type t =
  { msg_type: int32
  ; sender: int32
  ; receiver: int32
  ; ephemeral: bytes
  ; signed_empty: bytes
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
  -> receiver:int32
  -> ephemeral:bytes
  -> signed_empty:bytes
  -> t_cstruct
