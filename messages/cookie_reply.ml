type%cstruct t =
  { msg_type: uint32_t
  ; receiver: uint32_t
  ; nonce: uint8_t [@len 24]
  ; cookie: uint8_t [@len 32] }
[@@little_endian]

type t_cstruct = Cstruct.t

type t =
  { msg_type: Cstruct.uint32
  ; receiver: Cstruct.uint32
  ; nonce: bytes
  ; cookie: bytes }

let make_nice_blit func t bytes = func (Cstruct.of_bytes bytes) 0 t
let blit_t_nonce = make_nice_blit blit_t_nonce
let blit_t_cookie = make_nice_blit blit_t_cookie
let get_t_nonce t = get_t_nonce t |> Cstruct.to_bytes
let get_t_cookie t = get_t_cookie t |> Cstruct.to_bytes
let hexdump_t_cstruct = hexdump_t

let t_to_cstruct t =
  let ret = Cstruct.create sizeof_t in
  set_t_msg_type ret t.msg_type ;
  set_t_receiver ret t.receiver ;
  blit_t_nonce ret t.nonce ;
  blit_t_cookie ret t.cookie ;
  ret

let cstruct_to_t t_cstruct =
  let msg_type = get_t_msg_type t_cstruct in
  let receiver = get_t_receiver t_cstruct in
  let nonce = get_t_nonce t_cstruct in
  let cookie = get_t_cookie t_cstruct in
  {msg_type; receiver; nonce; cookie}

let create_t_cstruct ~receiver ~nonce ~cookie =
  let ret = Cstruct.create sizeof_t in
  set_t_msg_type ret (Constants.message_type_to_int Constants.COOKIE_REPLY) ;
  set_t_receiver ret receiver ;
  blit_t_nonce ret nonce ;
  blit_t_cookie ret cookie ;
  ret
