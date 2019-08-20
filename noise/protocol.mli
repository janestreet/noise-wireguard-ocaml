(* TODO: bin_io all the messages *)
open Async

val create_message_initiation :
     ?timestamp:Tai64n.t
  -> ?local_ephemeral:Crypto.keypair
  -> local_static_public:Crypto.Public.key
  -> Handshake.t
  -> Messages.Handshake_initiation.t_cstruct Deferred.Or_error.t

type peer

val consume_message_initiation :
     ?peer:peer
  -> msg:Messages.Handshake_initiation.t_cstruct
  -> local_static:Crypto.keypair
  -> peer Deferred.Or_error.t

val create_message_response :
     ?local_ephemeral:Crypto.keypair
  -> peer
  -> Messages.Handshake_response.t_cstruct Deferred.Or_error.t

val consume_message_response :
     ?handshake:Handshake.t
  -> ?local_static:Crypto.keypair
  -> Messages.Handshake_response.t_cstruct
  -> peer Deferred.Or_error.t

val begin_symmetric_session : peer -> unit Deferred.Or_error.t
