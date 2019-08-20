module Handshake_initiation : sig
  include module type of Handshake_initiation
end

module Handshake_response : sig
  include module type of Handshake_response
end

module Cookie_reply : sig
  include module type of Cookie_reply
end

module Transport : sig
  include module type of Transport
end

type mac_message =
  | Handshake_initiation of Handshake_initiation.t
  | Handshake_response of Handshake_response.t
  | Handshake_initiation_cstruct of Handshake_initiation.t_cstruct
  | Handshake_response_cstruct of Handshake_response.t_cstruct
  | Dummy_for_cookie_tests of Cstruct.t * bytes * bytes

val get_macs : mac_message -> Cstruct.t * bytes * Cstruct.t * bytes
val set_macs : msg:mac_message -> mac1:bytes -> mac2:bytes -> unit
val create_dummy : bytes -> mac_message
val xor_dummy : char -> mac_message -> unit
val hexdump_mac_message : mac_message -> unit
val get_dummy_msg_beta : msg_body:Cstruct.t -> mac1:bytes -> Cstruct.t

type t =
  | Handshake_initiation of Handshake_initiation.t
  | Handshake_response of Handshake_response.t
  | Cookie_reply of Cookie_reply.t
  | Transport of Transport.t
