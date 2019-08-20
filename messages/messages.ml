open Core
module Handshake_initiation = struct include Handshake_initiation end
module Handshake_response = struct include Handshake_response end
module Cookie_reply = struct include Cookie_reply end
module Transport = struct include Transport end

type mac_message =
  | Handshake_initiation of Handshake_initiation.t
  | Handshake_response of Handshake_response.t
  | Handshake_initiation_cstruct of Handshake_initiation.t_cstruct
  | Handshake_response_cstruct of Handshake_response.t_cstruct
  | Dummy_for_cookie_tests of Cstruct.t * bytes * bytes

let get_dummy_msg_beta ~msg_body ~mac1 =
  let body_length = Cstruct.len msg_body in
  let ret = Cstruct.create (body_length + 16) in
  Cstruct.blit msg_body 0 ret 0 body_length ;
  Cstruct.blit (Cstruct.of_bytes mac1) 0 ret body_length 16 ;
  ret

let get_macs (msg : mac_message) =
  let get_macs_init (m : Handshake_initiation.t) =
    (m.msg_alpha, !(m.mac1), m.msg_beta, !(m.mac2)) in
  let get_macs_resp (m : Handshake_response.t) =
    (m.msg_alpha, !(m.mac1), m.msg_beta, !(m.mac2)) in
  match msg with
  | Handshake_initiation m -> get_macs_init m
  | Handshake_response m -> get_macs_resp m
  | Handshake_initiation_cstruct m_cstruct ->
      Handshake_initiation.cstruct_to_t m_cstruct |> get_macs_init
  | Handshake_response_cstruct m_cstruct ->
      Handshake_response.cstruct_to_t m_cstruct |> get_macs_resp
  | Dummy_for_cookie_tests (msg_body, mac1, mac2) ->
      let msg_beta = get_dummy_msg_beta ~msg_body ~mac1 in
      (msg_body, mac1, msg_beta, mac2)

let set_macs ~(msg : mac_message) ~mac1 ~mac2 =
  match msg with
  | Handshake_initiation m ->
      m.mac1 := mac1 ;
      m.mac2 := mac2
  | Handshake_response m ->
      m.mac1 := mac1 ;
      m.mac2 := mac2
  | Handshake_initiation_cstruct m_cstruct ->
      Handshake_initiation.set_macs ~msg:m_cstruct ~mac1 ~mac2
  | Handshake_response_cstruct m_cstruct ->
      Handshake_response.set_macs ~msg:m_cstruct ~mac1 ~mac2
  | Dummy_for_cookie_tests (_, old_mac1, old_mac2) ->
      Bytes.blit ~src:mac1 ~src_pos:0 ~dst:old_mac1 ~dst_pos:0 ~len:16 ;
      Bytes.blit ~src:mac2 ~src_pos:0 ~dst:old_mac2 ~dst_pos:0 ~len:16

let create_dummy bytes =
  Dummy_for_cookie_tests
    (Cstruct.of_bytes bytes, Bytes.create 16, Bytes.create 16)

let xor_dummy byte =
  let byte_int = int_of_char byte in
  function
  | Dummy_for_cookie_tests (cstruct, _, _) ->
      for i = 0 to Cstruct.len cstruct - 1 do
        Cstruct.set_uint8 cstruct i (Cstruct.get_uint8 cstruct i lxor byte_int)
      done
  | _ -> ()

let pretty_print_bytes bytes = bytes |> Cstruct.of_bytes |> Cstruct.hexdump

let hexdump_mac_message = function
  | Handshake_initiation m ->
      Handshake_initiation.t_to_cstruct m
      |> Handshake_initiation.hexdump_t_cstruct
  | Handshake_response m ->
      Handshake_response.t_to_cstruct m |> Handshake_response.hexdump_t_cstruct
  | Handshake_initiation_cstruct m_cstruct ->
      Handshake_initiation.hexdump_t_cstruct m_cstruct
  | Handshake_response_cstruct m_cstruct ->
      Handshake_response.hexdump_t_cstruct m_cstruct
  | Dummy_for_cookie_tests (msg, old_mac1, old_mac2) ->
      Cstruct.hexdump msg ;
      print_string "mac1:" ;
      pretty_print_bytes old_mac1 ;
      print_string "mac2:" ;
      pretty_print_bytes old_mac2

type t =
  | Handshake_initiation of Handshake_initiation.t
  | Handshake_response of Handshake_response.t
  | Cookie_reply of Cookie_reply.t
  | Transport of Transport.t
