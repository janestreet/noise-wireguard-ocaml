type%cstruct t =
  { msg_type: uint32_t
  ; sender: uint32_t
  ; ephemeral: uint8_t [@len 32]
  ; signed_static: uint8_t [@len 48]
  ; signed_timestamp: uint8_t [@len 28]
  ; mac1: uint8_t [@len 32]
  ; mac2: uint8_t [@len 32] }
[@@little_endian]

type t_cstruct = Cstruct.t

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

let make_nice_blit func t bytes = func (Cstruct.of_bytes bytes) 0 t
let blit_t_ephemeral = make_nice_blit blit_t_ephemeral
let blit_t_signed_static = make_nice_blit blit_t_signed_static
let blit_t_signed_timestamp = make_nice_blit blit_t_signed_timestamp
let blit_t_mac1 = make_nice_blit blit_t_mac1
let blit_t_mac2 = make_nice_blit blit_t_mac2
let get_t_ephemeral t = get_t_ephemeral t |> Cstruct.to_bytes
let get_t_signed_static t = get_t_signed_static t |> Cstruct.to_bytes
let get_t_signed_timestamp t = get_t_signed_timestamp t |> Cstruct.to_bytes
let get_t_mac1 t = get_t_mac1 t |> Cstruct.to_bytes
let get_t_mac2 t = get_t_mac2 t |> Cstruct.to_bytes
let mac_size = 32

(* TODO: test get_t_msg_alpha get_t_msg_beta *)
let get_t_msg_alpha t = Cstruct.split t (Cstruct.len t - (2 * mac_size)) |> fst
let get_t_msg_beta t = Cstruct.split t (Cstruct.len t - mac_size) |> fst
let hexdump_t_cstruct = hexdump_t
let set_macs ~msg ~mac1 ~mac2 = blit_t_mac1 msg mac1 ; blit_t_mac2 msg mac2

let t_to_cstruct t =
  let ret = Cstruct.create sizeof_t in
  set_t_msg_type ret t.msg_type ;
  set_t_sender ret t.sender ;
  blit_t_ephemeral ret t.ephemeral ;
  blit_t_signed_static ret t.signed_static ;
  blit_t_signed_timestamp ret t.signed_timestamp ;
  blit_t_mac1 ret !(t.mac1) ;
  blit_t_mac2 ret !(t.mac2) ;
  ret

let cstruct_to_t t_cstruct =
  let msg_type = get_t_msg_type t_cstruct in
  let sender = get_t_sender t_cstruct in
  let ephemeral = get_t_ephemeral t_cstruct in
  let signed_static = get_t_signed_static t_cstruct in
  let signed_timestamp = get_t_signed_timestamp t_cstruct in
  let mac1 = get_t_mac1 t_cstruct |> ref in
  let mac2 = get_t_mac2 t_cstruct |> ref in
  let msg_alpha = get_t_msg_alpha t_cstruct in
  let msg_beta = get_t_msg_beta t_cstruct in
  { msg_type
  ; sender
  ; ephemeral
  ; signed_static
  ; signed_timestamp
  ; mac1
  ; mac2
  ; msg_alpha
  ; msg_beta }

let create_t_cstruct ~sender ~ephemeral ~signed_static ~signed_timestamp =
  let ret = Cstruct.create sizeof_t in
  set_t_msg_type ret
    (Constants.message_type_to_int Constants.HANDSHAKE_INITIATION) ;
  set_t_sender ret sender ;
  blit_t_ephemeral ret ephemeral ;
  blit_t_signed_static ret signed_static ;
  blit_t_signed_timestamp ret signed_timestamp ;
  ret
