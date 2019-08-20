open Core
open Key

let gen_tau_0 ~input ~key = Hash_blake2s.hmac ~input ~key |> Shared.of_bytes

let gen_next ~last ~tau_0 ~i =
  let last_len = Bytes.length last in
  let buf = Bytes.create (last_len + 1) in
  Bytes.blit ~src:last ~src_pos:0 ~dst:buf ~dst_pos:0 ~len:last_len ;
  Bytes.set buf last_len i ;
  Hash_blake2s.hmac ~key:tau_0 ~input:buf

let kdf_1 ~key input =
  let tau_0 = gen_tau_0 ~input ~key in
  let tau_1 = gen_next ~last:(Bytes.create 0) ~tau_0 ~i:'\x01' in
  Shared.set_zero tau_0 ; Shared.of_bytes tau_1

let kdf_2 ~key input =
  let tau_0 = gen_tau_0 ~input ~key in
  let tau_1 = gen_next ~last:(Bytes.create 0) ~tau_0 ~i:'\x01' in
  let tau_2 = gen_next ~last:tau_1 ~tau_0 ~i:'\x02' in
  Shared.set_zero tau_0 ;
  (Shared.of_bytes tau_1, Shared.of_bytes tau_2)

let kdf_3 ~key input =
  let tau_0 = gen_tau_0 ~input ~key in
  let tau_1 = gen_next ~last:(Bytes.create 0) ~tau_0 ~i:'\x01' in
  let tau_2 = gen_next ~last:tau_1 ~tau_0 ~i:'\x02' in
  let tau_3 = gen_next ~last:tau_2 ~tau_0 ~i:'\x03' in
  Shared.set_zero tau_0 ;
  (Shared.of_bytes tau_1, Shared.of_bytes tau_2, Shared.of_bytes tau_3)

let%expect_test "check_kdf" =
  Initialize.init () |> Or_error.ok_exn ;
  let input =
    Bytes.of_string
      "\x22\x11\xb3\x61\x08\x1a\xc5\x66\x69\x12\x43\xdb\x45\x8a\xd5\x32\x2d\x9c\x6c\x66\x22\x93\xe8\xb7\x0e\xe1\x9c\x65\xba\x07\x9e\xf3"
  in
  let key =
    Bytes.of_string
      "\x60\xe2\x6d\xae\xf3\x27\xef\xc0\x2e\xc3\x35\xe2\xa0\x25\xd2\xd0\x16\xeb\x42\x06\xf8\x72\x77\xf5\x2d\x38\xd1\x98\x8b\x78\xcd\x36"
    |> Shared.of_bytes in
  let tau_1, tau_2, tau_3 = kdf_3 ~key input in
  print_string (Shared.to_hex tau_1) ;
  print_string (Shared.to_hex tau_2) ;
  print_string (Shared.to_hex tau_3) ;
  [%expect
    {|
    e208 0118 5066 9fda 852f a82e 0cab d797
    4544 3369 3d32 888f 2a48 61cd b47a 65a7
    f3d9 5b70 6552 45b1 92ba bb51 a5c6 df9f
    b84e 908d 139c 1324 879d 6784 628a aa25
    aff9 b493 b751 fff4 247e 3da9 12a9 146b
    c862 f570 e9cb f5ae ba6d 8966 65c8 396b |}]
