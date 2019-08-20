type t

val get_t_send : t -> Crypto.Shared.key
val get_t_receive : t -> Crypto.Shared.key

val create_t :
     send_nonce:int64
  -> send:Crypto.Shared.key
  -> receive:Crypto.Shared.key
  -> replay_filter:int
  -> is_initiator:int
  -> created:Tai64n.t
  -> local_index:int32
  -> remote_index:int32
  -> t

val equal_t : t -> t -> bool

type ts = {current: t option; previous: t option; next: t option}

val create_empty_ts : unit -> ts
