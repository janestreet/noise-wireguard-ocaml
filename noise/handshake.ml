(* TODO: add finalizers *)

open Core
open Crypto

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

let zero_t_chain_key t = Shared.set_zero t.chain_key
let zero_t_hash t = zero_buffer t.hash
let zero_t_local_ephemeral t = zero_keypair t.local_ephemeral

open Or_error.Let_syntax

(* initiator.chaining_key = HASH(CONSTRUCTION)*)
(* TODO: put these in an init function *)
let initial_chain_key =
  Bytes.of_string
    "\x60\xe2\x6d\xae\xf3\x27\xef\xc0\x2e\xc3\x35\xe2\xa0\x25\xd2\xd0\x16\xeb\x42\x06\xf8\x72\x77\xf5\x2d\x38\xd1\x98\x8b\x78\xcd\x36"
  |> Shared.of_bytes

(* initiator.chaining_hash = HASH(initiator.chaining_key || IDENTIFIER) *)
let initial_chain_hash =
  Bytes.of_string
    "\x22\x11\xb3\x61\x08\x1a\xc5\x66\x69\x12\x43\xdb\x45\x8a\xd5\x32\x2d\x9c\x6c\x66\x22\x93\xe8\xb7\x0e\xe1\x9c\x65\xba\x07\x9e\xf3"

let init_handshake_chaining_vals t =
  let%bind () = copy_buffer ~src:initial_chain_hash ~dst:t.hash in
  Shared.copy ~src:initial_chain_key ~dst:t.chain_key

let mix_key handshake bytes : unit Or_error.t =
  let c_i = kdf_1 ~key:handshake.chain_key bytes in
  Shared.copy ~src:c_i ~dst:handshake.chain_key

let mix_key2 handshake bytes : Shared.key Or_error.t =
  let c_i, kappa = kdf_2 ~key:handshake.chain_key bytes in
  let%map () = Shared.copy ~src:c_i ~dst:handshake.chain_key in
  kappa

let mix_key3 handshake bytes : (Shared.key * Shared.key) Or_error.t =
  let c_i, tau, kappa = kdf_3 ~key:handshake.chain_key bytes in
  let%map () = Shared.copy ~src:c_i ~dst:handshake.chain_key in
  (tau, kappa)

let mix_hash handshake bytes : unit Or_error.t =
  let%bind result = hash2 handshake.hash bytes in
  Crypto.copy_buffer ~dst:handshake.hash ~src:result
