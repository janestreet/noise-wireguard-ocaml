open Core

external hash_ : bytes -> int -> bytes -> int = "caml_crypto_hash_blake2s"

let hash_bytes_out = 32

let hash input =
  let out_buf = Bytes.create hash_bytes_out in
  let status = hash_ input (Bytes.length input) out_buf in
  if status < 0 then
    Or_error.error_s [%message "failed to hash" (status : int)]
  else Or_error.return out_buf

let hash2 input1 input2 =
  let input =
    let l_1, l_2 = (Bytes.length input1, Bytes.length input2) in
    let buf = Bytes.create (l_1 + l_2) in
    Bytes.blit ~src:input1 ~src_pos:0 ~dst:buf ~dst_pos:0 ~len:l_1 ;
    Bytes.blit ~src:input2 ~src_pos:0 ~dst:buf ~dst_pos:l_1 ~len:l_2 ;
    buf in
  hash input

let%expect_test "check_blake2s" =
  let input = Bytes.of_string "Some data" in
  let digest = hash input |> Or_error.ok_exn in
  print_string
    (Hex.hexdump_s ~print_row_numbers:false ~print_chars:false
       (Hex.of_string (Bytes.to_string digest))) ;
  [%expect
    {|
    abba 30a7 cc0b cc97 4fd8 caaa d2c9 a2ca
    c689 7df0 1a59 8dd7 af3c 5a4a aa31 49c6|}]

external mac_ : bytes -> int -> bytes -> int -> bytes -> int
  = "caml_crypto_hash_keyed_blake2s"

let mac_bytes_out = 16

let mac ~input ~key =
  let out_buf = Bytes.create mac_bytes_out in
  let key = Key.Shared.to_bytes key in
  let status = mac_ input (Bytes.length input) key (Bytes.length key) out_buf in
  if status < 0 then Or_error.error_s [%message "failed to mac" (status : int)]
  else Or_error.return out_buf

let%expect_test "check_mac" =
  let input = Bytes.of_string "Some data" in
  let key = Bytes.of_string "secret" |> Key.Shared.of_bytes in
  let digest = mac ~input ~key |> Or_error.ok_exn in
  print_string
    (Hex.hexdump_s ~print_row_numbers:false ~print_chars:false
       (Hex.of_string (Bytes.to_string digest))) ;
  [%expect {| 3fb4 7e62 3d00 31b9 7f5f a77b 63ad d3c5 |}]

let hmac ~input ~key =
  let open Digestif in
  let key = Key.Shared.to_bytes key in
  BLAKE2S.hmac_bytes ~key input |> BLAKE2S.to_raw_string |> Bytes.of_string

let%expect_test "check_hmac" =
  let input = Bytes.of_string "Some data" in
  let key = Bytes.of_string "secret" |> Key.Shared.of_bytes in
  let digest = hmac ~input ~key in
  print_string
    (Hex.hexdump_s ~print_row_numbers:false ~print_chars:false
       (Hex.of_string (Bytes.to_string digest))) ;
  [%expect
    {|
     b704 ffb4 2f8a c808 0248 6f71 e50e f1f9
     bb8c 9f00 2190 542f 613f d2fb 3574 a4b3 |}]
