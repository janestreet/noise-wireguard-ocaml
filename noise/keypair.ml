type%cstruct t =
  { send_nonce: uint64_t
  ; send: uint8_t [@len 32]
  ; receive: uint8_t [@len 32]
  ; replay_filter: uint8_t
  ; is_initiator: uint8_t
  ; created: uint8_t [@len 12]
  ; local_index: uint32_t
  ; remote_index: uint32_t }
[@@little_endian]

type t = Cstruct.t

let make_nice_blit (func : Cstruct.t -> int -> t -> unit) : t -> bytes -> unit
    =
 fun t bytes ->
  let cs = Cstruct.of_bytes bytes in
  func cs 0 t

let get_t_send t = get_t_send t |> Cstruct.to_bytes |> Crypto.Shared.of_bytes
let blit_t_send = make_nice_blit blit_t_send

let get_t_receive t =
  get_t_receive t |> Cstruct.to_bytes |> Crypto.Shared.of_bytes

let blit_t_receive = make_nice_blit blit_t_receive
let blit_t_created = make_nice_blit blit_t_created

let create_t ~send_nonce ~send ~receive ~replay_filter ~is_initiator ~created
    ~local_index ~remote_index : t =
  let t = Cstruct.create sizeof_t in
  set_t_send_nonce t send_nonce ;
  blit_t_send t (Crypto.Shared.to_bytes send) ;
  blit_t_receive t (Crypto.Shared.to_bytes receive) ;
  set_t_replay_filter t replay_filter ;
  set_t_is_initiator t is_initiator ;
  blit_t_created t (Tai64n.to_bytes created) ;
  set_t_local_index t local_index ;
  set_t_remote_index t remote_index ;
  t

let equal_t t1 t2 = Cstruct.equal t1 t2

type ts = {current: t option; previous: t option; next: t option}

let create_empty_ts () = {current= None; previous= None; next= None}
