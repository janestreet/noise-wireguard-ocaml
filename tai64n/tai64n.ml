open Core
open Stdint

type t = {seconds: uint64; nanoseconds: uint32}

let base = Uint64.of_string "0x400000000000000a"
let billion = Uint64.of_int 1000000000

let time_to_t time =
  let since_epoch = Time_ns.to_span_since_epoch time in
  let ns_since_epoch =
    Time_ns.Span.to_int63_ns since_epoch |> Int63.to_int64 |> Uint64.of_int64
  in
  let seconds, nanoseconds =
    Uint64.(base + (ns_since_epoch / billion), rem ns_since_epoch billion)
  in
  {seconds; nanoseconds= Uint64.to_uint32 nanoseconds}

let epoch = time_to_t Time_ns.epoch

let to_bytes {seconds; nanoseconds} =
  let buf = Bytes.create 12 in
  Uint64.to_bytes_big_endian seconds buf 0 ;
  Uint32.to_bytes_big_endian nanoseconds buf 8 ;
  buf

let of_bytes buf =
  let secs = Uint64.of_bytes_big_endian buf 0 in
  let ns = Uint32.of_bytes_big_endian buf 8 in
  {seconds= secs; nanoseconds= ns}

let to_time t =
  let ns_total =
    Uint64.((billion * t.seconds) + of_uint32 t.nanoseconds)
    |> Uint64.to_int64 |> Int63.of_int64_exn in
  Time_ns.of_int63_ns_since_epoch ns_total

let diff t1 t2 =
  let time_1, time_2 = (to_time t1, to_time t2) in
  Time_ns.diff time_1 time_2

let whitener_mask = Uint32.of_int (0x1000000 - 1)

let whiten {seconds; nanoseconds} =
  let nanoseconds = Uint32.logand nanoseconds (Uint32.lognot whitener_mask) in
  {seconds; nanoseconds}

let get_timestamp time = time |> time_to_t |> whiten
let now () = get_timestamp (Time_ns.now ())
let since t = diff (now ()) t

let after t1 t2 =
  let b1, b2 = (to_bytes t1, to_bytes t2) in
  Bytes.compare b1 b2 > 0

let sleep_period =
  Time_ns.Span.to_sec (Time_ns.Span.of_int_ns (Uint32.to_int whitener_mask))

let%expect_test "test_tai64n_monotonic" =
  let old = ref (now ()) in
  for _ = 0 to 50 do
    let next = now () in
    if after next !old then print_s [%message "whitening insufficient"] ;
    Unix.nanosleep sleep_period |> ignore ;
    let next = now () in
    if not (after next !old) then
      print_s
        [%message "not monotonically increasing on whitened nanosecond scale"] ;
    old := next
  done ;
  [%expect {| |}]

let%expect_test "test_tai64n_since" =
  let old = now () in
  Unix.nanosleep sleep_period |> ignore ;
  if not Time_ns.Span.(since old > zero) then
    print_string "since sign is incorrect?" ;
  [%expect {| |}]
