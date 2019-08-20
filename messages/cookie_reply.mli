type t =
  { msg_type: Cstruct.uint32
  ; receiver: Cstruct.uint32
  ; nonce: bytes
  ; cookie: bytes }

type t_cstruct

val t_to_cstruct : t -> t_cstruct
val cstruct_to_t : t_cstruct -> t
val hexdump_t_cstruct : t_cstruct -> unit

val create_t_cstruct :
  receiver:int32 -> nonce:bytes -> cookie:bytes -> t_cstruct
