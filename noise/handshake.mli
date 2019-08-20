open Core

type noise_state =
  | Handshake_zeroed
  | Handshake_initiation_created
  | Handshake_initiation_consumed
  | Handshake_response_created
  | Handshake_response_consumed
[@@deriving sexp_of]

type t =
  { state: noise_state ref
  ; sequencer: unit Async.Throttle.Sequencer.t
  ; hash: bytes
  ; chain_key: Crypto.Shared.key
  ; preshared_key: Crypto.Shared.key
  ; local_ephemeral: Crypto.keypair
  ; (* localIndex is used to clear hash-table *)
    local_index: Cstruct.uint32 ref
  ; remote_index: Cstruct.uint32 ref
  ; remote_static: Crypto.Public.key
  ; remote_ephemeral: Crypto.Public.key
  ; precomputed_static_static: Crypto.Shared.key
  ; last_timestamp: Tai64n.t ref
  ; last_initiation_consumption: Tai64n.t ref
  ; last_sent_handshake: Tai64n.t ref }

val initial_chain_key : Crypto.Shared.key
val initial_chain_hash : bytes
val init_handshake_chaining_vals : t -> unit Or_error.t
val zero_t_chain_key : t -> unit
val zero_t_hash : t -> unit
val zero_t_local_ephemeral : t -> unit
val mix_key : t -> bytes -> unit Or_error.t
val mix_key2 : t -> bytes -> Crypto.Shared.key Or_error.t
val mix_key3 : t -> bytes -> (Crypto.Shared.key * Crypto.Shared.key) Or_error.t
val mix_hash : t -> bytes -> unit Or_error.t
