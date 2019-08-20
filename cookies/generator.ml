open Core
open Or_error.Let_syntax

type t =
  { mac1_key: Crypto.Shared.key
  ; mac2_cookie: bytes
  ; mac2_cookie_set: Time_ns.t ref
  ; mac2_has_last_mac1: bool ref
  ; mac2_last_mac1: bytes
  ; mac2_encryption_key: Crypto.Shared.key }

let _hexdump t =
  print_string "mac1_key" ;
  Crypto.Shared.to_bytes t.mac1_key |> Cstruct.of_bytes |> Cstruct.hexdump ;
  print_string "mac2_cookie" ;
  t.mac2_cookie |> Cstruct.of_bytes |> Cstruct.hexdump ;
  print_s
    [%message
      (!(t.mac2_cookie_set) : Time_ns.t) (!(t.mac2_has_last_mac1) : bool)] ;
  print_string "mac2_last_mac1" ;
  t.mac2_last_mac1 |> Cstruct.of_bytes |> Cstruct.hexdump ;
  print_string "mac2_encryption_key" ;
  Crypto.Shared.to_bytes t.mac2_encryption_key
  |> Cstruct.of_bytes |> Cstruct.hexdump

let init pk : t Or_error.t =
  let%map mac1_key, mac2_encryption_key = Constants.init_constants pk in
  { mac1_key
  ; mac2_cookie= Bytes.create 16
  ; mac2_cookie_set= ref Time_ns.epoch
  ; mac2_has_last_mac1= ref false
  ; mac2_last_mac1= Bytes.create 16
  ; mac2_encryption_key }

let consume_reply ~t ~(msg : Messages.Cookie_reply.t_cstruct) : unit Or_error.t
    =
  let msg = Messages.Cookie_reply.cstruct_to_t msg in
  if not !(t.mac2_has_last_mac1) then
    Or_error.error_string "no last mac1 for cookie reply"
  else
    let%bind cookie =
      Crypto.xaead_decrypt ~key:t.mac2_encryption_key ~nonce:msg.nonce
        ~ciphertext:msg.cookie ~auth_text:t.mac2_last_mac1 in
    t.mac2_cookie_set := Time_ns.now () ;
    Crypto.copy_buffer ~dst:t.mac2_cookie ~src:cookie

let add_macs ~t ~(msg : Messages.mac_message) : unit Or_error.t =
  let msg_alpha, _, _, _ = Messages.get_macs msg in
  let%bind mac1 =
    Crypto.mac ~key:t.mac1_key ~input:(Cstruct.to_bytes msg_alpha) in
  let%bind () = Crypto.copy_buffer ~src:mac1 ~dst:t.mac2_last_mac1 in
  t.mac2_has_last_mac1 := true ;
  let msg_beta = Messages.get_dummy_msg_beta ~msg_body:msg_alpha ~mac1 in
  let%map mac2 =
    if
      Time_ns.Span.(
        Time_ns.(diff (now ()) !(t.mac2_cookie_set))
        > Constants.cookie_refresh_time)
    then Bytes.make 32 '\x00' |> Or_error.return
    else
      Crypto.mac
        ~key:(Crypto.Shared.of_bytes t.mac2_cookie)
        ~input:(Cstruct.to_bytes msg_beta) in
  Messages.set_macs ~msg ~mac1 ~mac2
