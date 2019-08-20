open Core
open Or_error.Let_syntax

type t =
  { mac1_key: Crypto.Shared.key
  ; mac2_secret: Crypto.Shared.key
  ; mac2_secret_set: Time_ns.t ref
  ; mac2_encryption_key: Crypto.Shared.key }

let init pk : t Or_error.t =
  let%map mac1_key, mac2_encryption_key = Constants.init_constants pk in
  { mac1_key
  ; mac2_secret= Crypto.Shared.create_uninit ()
  ; mac2_secret_set= ref Time_ns.epoch
  ; mac2_encryption_key }

let check_mac1 ~t ~(msg_alpha : Cstruct.t) ~(mac1_r : bytes) : unit Or_error.t
    =
  let%bind mac1 =
    Crypto.mac ~key:t.mac1_key ~input:(Cstruct.to_bytes msg_alpha) in
  Result.ok_if_true
    ~error:(Error.of_string "mac1 check failed!")
    (Bytes.equal mac1 mac1_r)

(* src is concatenation of external IP src address and UDP port *)
let check_mac2 ~t ~(msg_beta : Cstruct.t) ~(mac2_r : bytes) ~(src : bytes) :
    unit Or_error.t =
  let%bind () =
    Result.ok_if_true
      Time_ns.Span.(
        Time_ns.(diff (now ()) !(t.mac2_secret_set))
        <= Constants.cookie_refresh_time)
      ~error:(Error.of_string "cookie expired") in
  let%bind cookie =
    Crypto.mac ~key:t.mac2_secret ~input:src >>| Crypto.Shared.of_bytes in
  let%bind mac2 = Crypto.mac ~key:cookie ~input:(Cstruct.to_bytes msg_beta) in
  Result.ok_if_true
    ~error:(Error.of_string "mac2 check failed!")
    (Bytes.equal mac2 mac2_r)

let check_macs ?(should_check_mac2 = true) ~t ~msg ~src : unit Or_error.t =
  let msg_alpha, mac1_r, msg_beta, mac2_r = Messages.get_macs msg in
  let%bind () = check_mac1 ~t ~msg_alpha ~mac1_r in
  if should_check_mac2 then check_mac2 ~t ~msg_beta ~mac2_r ~src else Ok ()

(* msg is incoming message prompting cookie reply msg *)
(* recv is receiver id from msg.sender of message *)
(* src is concatenation of external IP src address and UDP port *)
let create_reply ~t ~msg ~receiver ~src :
    Messages.Cookie_reply.t_cstruct Or_error.t =
  let%bind () =
    if
      Time_ns.Span.(
        Time_ns.(diff (now ()) !(t.mac2_secret_set))
        >= Constants.cookie_refresh_time)
    then (
      t.mac2_secret_set := Time_ns.now () ;
      let mac2_secret = Crypto.random_buffer 32 in
      Crypto.Shared.copy_from_bytes t.mac2_secret mac2_secret )
    else Ok () in
  let%bind tau = Crypto.mac ~key:t.mac2_secret ~input:src in
  let _, mac1_r, _, _ = Messages.get_macs msg in
  let nonce = Crypto.random_buffer 24 in
  let%map cookie =
    Crypto.xaead_encrypt ~key:t.mac2_encryption_key ~nonce ~message:tau
      ~auth_text:mac1_r in
  Messages.Cookie_reply.create_t_cstruct ~nonce ~cookie ~receiver
