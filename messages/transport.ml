type%cstruct transport_header =
  {msg_type: uint32_t; receiver: uint32_t; counter: uint64_t}
[@@little_endian]

type transport_header = Cstruct.t
type t = transport_header * bytes
