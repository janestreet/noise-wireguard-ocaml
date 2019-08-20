open Core

external random_buffer_ : Bytes.t -> int -> unit = "caml_crypto_gen_key"

let random_buffer len =
  let buf = Bytes.make len '\x00' in
  random_buffer_ buf len ; buf

let zero_buffer buf = Bytes.fill ~pos:0 ~len:(Bytes.length buf) buf '\x00'

let copy_buffer ~src ~dst =
  if not (Bytes.length src = Bytes.length dst) then
    Or_error.error_s
      [%message
        "trying to copy buffers of unequal lengths"
          (Bytes.length src : int)
          (Bytes.length dst : int)]
  else Ok (Bytes.blit ~src ~src_pos:0 ~dst ~dst_pos:0 ~len:(Bytes.length src))

(* TODO: figure out constant time equality *)
let equals b1 b2 = Bytes.equal b1 b2

let is_zero bytes : bool =
  let buf = Bytes.make (Bytes.length bytes) '\x00' in
  Bytes.equal bytes buf

module type Key_utils = sig
  type key [@@deriving sexp_of]

  val to_hex : key -> string
  val of_hex : ?len:int -> string -> key Or_error.t
  val set_zero : key -> unit
  val of_bytes : bytes -> key
  val to_bytes : key -> bytes
  val copy_from_bytes : key -> bytes -> unit Or_error.t
  val copy_to_bytes : key -> bytes -> unit Or_error.t
  val copy : src:key -> dst:key -> unit Or_error.t
  val equals : key -> key -> bool
  val is_zero : key -> bool
  val clone : key -> key
  val create_uninit : unit -> key
end

module Make_key_utils (S : sig end) : Key_utils = struct
  type key = bytes [@@deriving sexp_of]

  let to_hex (key : bytes) : string =
    Hex.hexdump_s ~print_row_numbers:false ~print_chars:false
      (key |> Bytes.to_string |> Hex.of_string)

  let of_hex ?len str : key Or_error.t =
    try
      let bytes = Hex.to_bytes (`Hex str) in
      ( match len with
      | None -> ()
      | Some len -> assert (Bytes.length bytes = len) ) ;
      Ok bytes
    with _ -> Or_error.error_string "failed to convert key from hex string"

  let set_zero (bytes : key) : unit = zero_buffer bytes
  let of_bytes bytes = bytes
  let to_bytes bytes = bytes
  let copy_from_bytes key bytes = copy_buffer ~src:bytes ~dst:key
  let copy_to_bytes key bytes = copy_buffer ~src:key ~dst:bytes
  let copy ~src ~dst = copy_buffer ~src ~dst
  let equals key1 key2 = equals key1 key2
  let is_zero bytes : bool = is_zero bytes
  let clone key = Bytes.copy key
  let create_uninit () = Bytes.create 32
end

module Shared = Make_key_utils ()

module Secret = struct
  include Make_key_utils ()

  let generate_key ~len : key = random_buffer len |> of_bytes
end

module Public = struct include Make_key_utils () end

type keypair = {secret: Secret.key; public: Public.key} [@@deriving sexp_of]

let copy_keypair ~src ~dst : unit Or_error.t =
  Or_error.bind (Secret.copy ~src:src.secret ~dst:dst.secret) ~f:(fun () ->
      Public.copy ~src:src.public ~dst:dst.public)

let zero_keypair keypair : unit =
  Secret.set_zero keypair.secret ;
  Public.set_zero keypair.public
