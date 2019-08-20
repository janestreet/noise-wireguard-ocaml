open Core
open Or_error.Let_syntax

let int_list_to_bytes (int_list : int list) : bytes =
  let char_list = List.map ~f:char_of_int int_list in
  Bytes.of_char_list char_list

let src = Hex.to_string (`Hex "c0a80d250a0a0a") |> Bytes.of_string

let is_error = function
  | Ok _ -> Or_error.error_s [%message "this should be an error!"]
  | Error _ -> Ok ()

let check_mac1 ~gen ~check ~msg =
  let%bind () = Generator.add_macs ~t:gen ~msg in
  Checker.check_macs ~should_check_mac2:false ~t:check ~msg ~src

let check_mac2 ~gen ~check ~msg =
  let%bind () = Generator.add_macs ~t:gen ~msg in
  let%bind () = Checker.check_macs ~should_check_mac2:true ~t:check ~msg ~src in
  Messages.xor_dummy '\x20' msg ;
  let%bind () =
    Checker.check_macs ~should_check_mac2:true ~t:check ~msg ~src |> is_error
  in
  Messages.xor_dummy '\x20' msg ;
  (* TODO: change these to hex strings and remove int_list_to_bytes *)
  let src_bad1 = int_list_to_bytes [192; 168; 13; 37; 40; 01] in
  let%bind () =
    Checker.check_macs ~should_check_mac2:true ~t:check ~msg ~src:src_bad1
    |> is_error in
  let src_bad2 = int_list_to_bytes [192; 168; 13; 38; 40; 01] in
  Checker.check_macs ~should_check_mac2:true ~t:check ~msg ~src:src_bad2
  |> is_error

let%expect_test "test_cookies_against_go" =
  (let%bind () = Crypto.init () in
   let%bind key = Crypto.generate () in
   let%bind check = Checker.init key.public in
   let%bind gen = Generator.init key.public in
   (******* CHECKING MAC1 *******)
   let%bind () =
     let msg =
       Hex.to_string
         (`Hex
           "99bba5fc99aa83bd7b00c59a4cb9cf624023f38ed8d062645db28013dacec69161d630f132b3a2f47b43b5a7e2b1f56c746bb0cd1f94867bc8fb92ed549b44f5c87db78eff49c4e8397c19e0601951f8e48e02f17f1dcc8eb007fff8af7f6682")
       |> Bytes.of_string |> Messages.create_dummy in
     check_mac1 ~gen ~check ~msg in
   let%bind () =
     let msg =
       Hex.to_string
         (`Hex
           "33e72a849fff576c2dc32de1f55c9756b893c27dd441dd7a4a593b50dd7a7a8c")
       |> Bytes.of_string |> Messages.create_dummy in
     check_mac1 ~gen ~check ~msg in
   let%bind () =
     let msg =
       Hex.to_string (`Hex "") |> Bytes.of_string |> Messages.create_dummy
     in
     check_mac1 ~gen ~check ~msg in
   (******* CHECKING COOKIE REPLY *******)
   let msg =
     Hex.to_string
       (`Hex
         "6dd7c32eb076d8df30657d623ef89ae8e73c64a37848daf5256128537932869fa0279569b6bad0a2f868eaa862f2fd1be0b480e56b3a169e35f6a8f24f9a7be9770bc2b4edbaf922c30397429f797427fef9066e973aa68fc9570a544c644ae2b9ec76ac2e16fb0cca0e079566a256b4632af16d46cb2f618ce1e8fa6720806d")
     |> Bytes.of_string |> Messages.create_dummy in
   let%bind () = Generator.add_macs ~t:gen ~msg in
   let%bind cookie_reply =
     Checker.create_reply ~t:check ~msg ~receiver:(Int32.of_int_exn 1377) ~src
   in
   let%bind () = Generator.consume_reply ~t:gen ~msg:cookie_reply in
   (******* CHECKING MAC2 *******)
   let%bind () =
     let msg =
       Hex.to_string
         (`Hex
           "0331b99eb02a54a3c13fb49616b925153d3a82f95836863f132ffeb253208c3f")
       |> Bytes.of_string |> Messages.create_dummy in
     check_mac2 ~gen ~check ~msg in
   let msg =
     Hex.to_string
       (`Hex
         "0e2f0ea92903e1f3240175ad16a56685ca66e0bdc634d884099a5814fb05daf590f50c4e2210c9850fe37735e96bc2553246ae25e0e3377a4b71ccfc91dfd6cafeeece3f77a2fd598e730a8d5c2414ca3891b82c8ca2657bbc49bcb558fce3d702cff74c6091ed55e9f9fed1442c75f2b35d7b2756c0484fb0bae47dd0aacd3de350d2cfb9fa4b2dc6df3b329845e68f1c5ca2207d1c28c2d4a1e021528f1cd0629748bbf4a9cb35f207d350d8a9c59a0fbd37afe14519ee41f3f7e5e0303fbe3d3964007a1a515ee1700bb9775af0c48aa13a771ae0c20691d5e91cd3feab93")
     |> Bytes.of_string |> Messages.create_dummy in
   check_mac2 ~gen ~check ~msg)
  |> Or_error.ok_exn ;
  [%expect {| |}]
