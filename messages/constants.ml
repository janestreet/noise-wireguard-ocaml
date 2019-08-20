(* size of handshake initation message *)
let msg_initiation_size = 148

(* size of response message *)
let _msg_response_size = 92

(* size of cookie reply message *)
let _msg_cookie_reply_size = 64

(* size of data preceeding content in transport message *)
let msg_transport_header_size = 16

(* size of empty transport *)
let msg_transport_size = msg_transport_header_size + Crypto.poly1305_tag_size

(* size of keepalive *)
let _msg_keep_alive_size = msg_transport_size

(* size of largest handshake releated message *)
let _msg_handshake_size = msg_initiation_size

(* offsets of interesting things inside transpost messages *)
let _msg_transport_offset_receiver = 4
let _msg_transport_offset_counter = 8
let _msg_transport_offset_content = 16

type%cenum message_type =
  | HANDSHAKE_INITIATION [@id 1]
  | HANDSHAKE_RESPONSE [@id 2]
  | COOKIE_REPLY [@id 3]
  | TRANSPORT [@id 4]
[@@uint32_t]
