open Core
open Stdint
open Crypto
open Async
open Or_error.Let_syntax

(* TODO: for testing, remove! *)
let handshake_1_index = Int32.of_int 3
let _handshake_2_index = Int32.of_int 2

(* TODO: worry about clearing and managing memory later. *)
let empty_bytes () = Bytes.create 0

(* various nothing-up-my-sleeve constants *)
let _noise_construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
let _wg_identifier = "WireGuard v1 zx2c4 Jason@zx2c4.com"
let handshake_initiation_rate : Time_ns.Span.t = Time_ns.Span.of_int_ms 20

type peer = {handshake: Handshake.t; keypairs: Keypair.ts ref}

(* optionally pass in constants for values that should be generated *)
(* just for testing! *)
let create_message_initiation ?timestamp ?local_ephemeral
    ~(local_static_public : Public.key) (handshake : Handshake.t) :
    Messages.Handshake_initiation.t_cstruct Deferred.Or_error.t =
  Throttle.enqueue handshake.sequencer (fun () ->
      Deferred.return
        (let%bind () =
           Result.ok_if_true
             (not (Crypto.Shared.is_zero handshake.precomputed_static_static))
             ~error:(Error.of_string "handshake precomputed static is zero")
         in
         let%bind () = Handshake.init_handshake_chaining_vals handshake in
         (* create ephemeral key *)
         let%bind () =
           let%bind local_ephemeral =
             match local_ephemeral with
             | Some le -> Ok le
             | None -> generate () in
           Crypto.copy_keypair ~src:local_ephemeral
             ~dst:handshake.local_ephemeral in
         (* assign index *)
         handshake.local_index := handshake_1_index ;
         let%bind () =
           Handshake.mix_hash handshake
             (Crypto.Public.to_bytes handshake.remote_static) in
         let ephemeral =
           handshake.local_ephemeral.public |> Crypto.Public.to_bytes in
         let%bind () = Handshake.mix_key handshake ephemeral in
         let%bind () = Handshake.mix_hash handshake ephemeral in
         (* encrypt static key *)
         let%bind ephemeral_shared =
           dh ~secret:handshake.local_ephemeral.secret
             ~public:handshake.remote_static in
         let%bind kappa =
           Handshake.mix_key2 handshake (Shared.to_bytes ephemeral_shared)
         in
         let%bind signed_static =
           aead_encrypt ~key:kappa ~counter:(Int64.of_int 0)
             ~message:(Public.to_bytes local_static_public)
             ~auth_text:handshake.hash in
         let%bind () = Handshake.mix_hash handshake signed_static in
         (* encrypt timestamp *)
         let timestamp =
           (match timestamp with Some ts -> ts | None -> Tai64n.now ())
           |> Tai64n.to_bytes in
         let%bind kappa =
           Handshake.mix_key2 handshake
             (Shared.to_bytes handshake.precomputed_static_static) in
         let%bind () =
           Shared.copy ~src:kappa ~dst:handshake.precomputed_static_static
         in
         let%bind signed_timestamp =
           aead_encrypt ~key:kappa ~counter:(Int64.of_int 0) ~message:timestamp
             ~auth_text:handshake.hash in
         let%map () = Handshake.mix_hash handshake signed_timestamp in
         handshake.state := Handshake.Handshake_initiation_created ;
         Messages.Handshake_initiation.create_t_cstruct ~ephemeral
           ~sender:!(handshake.local_index) ~signed_timestamp ~signed_static))

let mix_key ~chain_key bytes : unit Or_error.t =
  let c_i = kdf_1 ~key:chain_key bytes in
  Shared.copy ~src:c_i ~dst:chain_key

let mix_key2 ~chain_key bytes : Shared.key Or_error.t =
  let c_i, kappa = kdf_2 ~key:chain_key bytes in
  let%map () = Shared.copy ~src:c_i ~dst:chain_key in
  kappa

let mix_hash ~hash bytes : unit Or_error.t =
  let%bind res = hash2 hash bytes in
  Crypto.copy_buffer ~src:res ~dst:hash

(* peer arg for testing only! should not be passed in in prod. *)
let consume_message_initiation ?peer
    ~(msg : Messages.Handshake_initiation.t_cstruct) ~(local_static : keypair)
    : peer Deferred.Or_error.t =
  let open Deferred.Or_error.Let_syntax in
  let hash = Bytes.copy Handshake.initial_chain_hash in
  let chain_key : Shared.key = Shared.clone Handshake.initial_chain_key in
  let%bind () =
    Deferred.return (mix_hash ~hash (Public.to_bytes local_static.public))
  in
  let msg = Messages.Handshake_initiation.cstruct_to_t msg in
  let%bind () = Deferred.return (mix_hash ~hash msg.ephemeral) in
  let%bind () = Deferred.return (mix_key ~chain_key msg.ephemeral) in
  (* decrypt static key *)
  let%bind ephemeral_shared =
    Deferred.return
      (dh ~secret:local_static.secret ~public:(Public.of_bytes msg.ephemeral))
  in
  let%bind kappa =
    Deferred.return (mix_key2 ~chain_key (Shared.to_bytes ephemeral_shared))
  in
  let%bind peer_pk =
    Deferred.return
      (aead_decrypt ~key:kappa ~counter:(Int64.of_int 0)
         ~ciphertext:msg.signed_static ~auth_text:hash) in
  let%bind () = Deferred.return (mix_hash ~hash msg.signed_static) in
  (* lookup peer *)
  let peer =
    match peer with Some peer -> peer | None -> failwith "unimplemented" in
  let handshake = peer.handshake in
  let%map () =
    Throttle.enqueue handshake.sequencer (fun () ->
        Deferred.return
          (let open (* TODO: change this to something sensical.... *)
                      Or_error.Let_syntax in
          assert (Bytes.equal peer_pk (Public.to_bytes handshake.remote_static)) ;
          let pss = handshake.precomputed_static_static in
          (* TODO: make this a function *)
          let%bind () =
            Result.ok_if_true
              (not (Crypto.Shared.is_zero pss))
              ~error:(Error.of_string "handshake precomputed static is zero")
          in
          let%bind () = Handshake.init_handshake_chaining_vals handshake in
          (* verify identity *)
          let%bind kappa = mix_key2 ~chain_key (Shared.to_bytes pss) in
          let%bind timestamp =
            aead_decrypt ~key:kappa ~counter:(Int64.of_int 0)
              ~ciphertext:msg.signed_timestamp ~auth_text:hash in
          let%bind () = mix_hash ~hash msg.signed_timestamp in
          (* protect against replays, floods *)
          let%bind () =
            let ok =
              Tai64n.after
                (Tai64n.of_bytes timestamp)
                !(handshake.last_timestamp)
              && Time_ns.Span.(
                   Tai64n.diff (Tai64n.now ())
                     !(handshake.last_initiation_consumption)
                   > handshake_initiation_rate) in
            Result.ok_if_true ok
              ~error:
                (Error.of_string "insufficient time since last initiation")
          in
          let%bind () = Crypto.copy_buffer ~src:hash ~dst:handshake.hash in
          let%bind () =
            Crypto.Shared.copy ~dst:handshake.chain_key ~src:chain_key in
          handshake.remote_index := msg.sender ;
          let%map () =
            Public.copy ~dst:handshake.remote_ephemeral
              ~src:(Public.of_bytes msg.ephemeral) in
          handshake.last_timestamp := Tai64n.of_bytes timestamp ;
          handshake.last_initiation_consumption := Tai64n.now () ;
          handshake.state := Handshake.Handshake_initiation_consumed)) in
  Crypto.zero_buffer hash ;
  Shared.set_zero chain_key ;
  {handshake; keypairs= ref (Keypair.create_empty_ts ())}

let int_list_to_bytes int_list =
  let char_list = List.map ~f:char_of_int int_list in
  Bytes.of_char_list char_list

let pretty_print_bytes bytes = bytes |> Cstruct.of_bytes |> Cstruct.hexdump

let create_message_response ?local_ephemeral peer :
    Messages.Handshake_response.t_cstruct Deferred.Or_error.t =
  let handshake = peer.handshake in
  let create_message_response_ () =
    Throttle.enqueue handshake.sequencer (fun () ->
        Deferred.return
          (let sender = !(handshake.local_index) in
           let receiver = !(handshake.remote_index) in
           let%bind local_ephemeral =
             match local_ephemeral with
             | Some le -> Ok le
             | None -> generate () in
           let%bind () =
             Crypto.copy_keypair ~dst:handshake.local_ephemeral
               ~src:local_ephemeral in
           let ephemeral = Public.to_bytes local_ephemeral.public in
           let%bind () = Handshake.mix_hash handshake ephemeral in
           let%bind () = Handshake.mix_key handshake ephemeral in
           let%bind ephemeral_shared =
             dh ~secret:local_ephemeral.secret
               ~public:handshake.remote_ephemeral in
           let%bind () =
             Handshake.mix_key handshake (Shared.to_bytes ephemeral_shared)
           in
           let%bind static_shared =
             dh ~secret:local_ephemeral.secret ~public:handshake.remote_static
           in
           let%bind () =
             Handshake.mix_key handshake (Shared.to_bytes static_shared) in
           let%bind tau, kappa =
             Handshake.mix_key3 handshake
               (Shared.to_bytes handshake.preshared_key) in
           let%bind () = Handshake.mix_hash handshake (Shared.to_bytes tau) in
           let%bind signed_empty =
             aead_encrypt ~key:kappa ~counter:(Int64.of_int 0)
               ~message:(empty_bytes ()) ~auth_text:handshake.hash in
           let%map () = Handshake.mix_hash handshake signed_empty in
           handshake.state := Handshake.Handshake_response_created ;
           Messages.Handshake_response.create_t_cstruct ~sender ~receiver
             ~ephemeral ~signed_empty)) in
  match !(handshake.state) with
  | Handshake.Handshake_initiation_consumed -> create_message_response_ ()
  | state ->
      Deferred.Or_error.error_s
        [%message
          "handshake is in the wrong state to call create_message_response!"
            (state : Handshake.noise_state)]

(* in real implementation, lookup handshake by receiver id *)
(* in real implementation get local_static from device *)
let consume_message_response ?handshake ?local_static
    (msg : Messages.Handshake_response.t_cstruct) : peer Deferred.Or_error.t =
  let open Deferred.Or_error.Let_syntax in
  let msg = Messages.Handshake_response.cstruct_to_t msg in
  let%bind handshake =
    match (handshake : Handshake.t option) with
    | Some handshake -> Ok handshake |> Deferred.return
    | None -> Deferred.Or_error.error_string "unimplemented handshake lookup"
  in
  let handshake : Handshake.t = handshake in
  Throttle.enqueue handshake.sequencer (fun () ->
      Deferred.return
        (let open Or_error.Let_syntax in
        let%bind () =
          match !(handshake.state) with
          | Handshake.Handshake_initiation_created -> Ok ()
          | state ->
              Or_error.error_s
                [%message
                  "handshake is in the wrong state to call \
                   consume_message_response!"
                    (state : Handshake.noise_state)] in
        let%bind () = Handshake.mix_hash handshake msg.ephemeral in
        let%bind () = Handshake.mix_key handshake msg.ephemeral in
        let%bind ephemeral_shared =
          dh ~secret:handshake.local_ephemeral.secret
            ~public:(Public.of_bytes msg.ephemeral) in
        let%bind () =
          Handshake.mix_key handshake (Shared.to_bytes ephemeral_shared) in
        Shared.set_zero ephemeral_shared ;
        let%bind local_static =
          match local_static with
          | Some local_static -> Ok local_static
          | None -> Or_error.error_string "unimplemented handshake lookup"
        in
        let%bind static_shared =
          dh ~secret:local_static.secret
            ~public:(Public.of_bytes msg.ephemeral) in
        let%bind () =
          Handshake.mix_key handshake (Shared.to_bytes static_shared) in
        Shared.set_zero static_shared ;
        let%bind tau, kappa =
          Handshake.mix_key3 handshake
            (Shared.to_bytes handshake.preshared_key) in
        let%bind () = Handshake.mix_hash handshake (Shared.to_bytes tau) in
        let%bind _empty =
          aead_decrypt ~key:kappa ~counter:(Int64.of_int 0)
            ~ciphertext:msg.signed_empty ~auth_text:handshake.hash in
        let%map () = Handshake.mix_hash handshake msg.signed_empty in
        handshake.state := Handshake.Handshake_response_consumed ;
        {handshake; keypairs= ref (Keypair.create_empty_ts ())}))

let begin_symmetric_session peer : unit Deferred.Or_error.t =
  let handshake = peer.handshake in
  Throttle.enqueue handshake.sequencer (fun () ->
      Deferred.return
        (let open Or_error.Let_syntax in
        let%map (send, receive), is_initiator =
          match !(handshake.state) with
          | Handshake_response_consumed ->
              (Crypto.kdf_2 ~key:handshake.chain_key (empty_bytes ()), true)
              |> Or_error.return
          | Handshake_response_created ->
              Crypto.kdf_2 ~key:handshake.chain_key (empty_bytes ())
              |> fun (a, b) -> ((b, a), false) |> Or_error.return
          | _ -> Or_error.error_string "invalid state for keypair derivation"
        in
        Handshake.zero_t_chain_key handshake ;
        Handshake.zero_t_hash handshake ;
        Handshake.zero_t_local_ephemeral handshake ;
        handshake.state := Handshake.Handshake_zeroed ;
        let open Keypair in
        let keypair =
          create_t ~send_nonce:Int64.zero ~send ~receive ~replay_filter:0
            ~is_initiator:(if is_initiator then 1 else 0)
            ~created:(Tai64n.now ()) ~local_index:!(handshake.local_index)
            ~remote_index:!(handshake.remote_index) in
        let {current; previous= _; next} = !(peer.keypairs) in
        let keypairs =
          if is_initiator then
            let next, previous =
              match next with Some _ -> (None, next) | None -> (next, current)
            in
            let current = Some keypair in
            {current; next; previous}
          else {current; previous= None; next= Some keypair} in
        peer.keypairs := keypairs))

let test_key_pairs peer1 peer2 : unit Or_error.t =
  let%bind send1, receive1 =
    match !(peer1.keypairs).next with
    | Some n -> Ok (Keypair.get_t_send n, Keypair.get_t_receive n)
    | None -> Or_error.error_string "no next key for peer1" in
  let%bind send2, receive2 =
    match !(peer2.keypairs).current with
    | Some n -> Ok (Keypair.get_t_send n, Keypair.get_t_receive n)
    | None -> Or_error.error_string "no current key for peer2" in
  let auth_text = empty_bytes () in
  let m_1 = Bytes.of_string "wireguard test message 1" in
  let ctr_1 = Int64.of_int 13289420 in
  let%bind c_1 =
    Crypto.aead_encrypt ~key:send1 ~counter:ctr_1 ~message:m_1 ~auth_text in
  let%bind m_1_dec =
    Crypto.aead_decrypt ~key:receive2 ~counter:ctr_1 ~ciphertext:c_1 ~auth_text
  in
  let m_2 = Bytes.of_string "wireguard test message 2" in
  let ctr_2 = Int64.of_int 43290128 in
  let%bind c_2 =
    Crypto.aead_encrypt ~key:send2 ~counter:ctr_2 ~message:m_2 ~auth_text in
  let%bind m_2_dec =
    Crypto.aead_decrypt ~key:receive1 ~counter:ctr_2 ~ciphertext:c_2 ~auth_text
  in
  if Bytes.equal m_1 m_1_dec && Bytes.equal m_2 m_2_dec then Ok ()
  else Or_error.error_string "failed correct encryption and decryption..."

let%expect_test "test_handshake_against_go_constants" =
  Crypto.init () |> Or_error.ok_exn ;
  (* all constants from output of wireguard-go tests *)
  (* local and remote static keys *)
  let open Deferred.Let_syntax in
  let%bind () =
    (let dev1_static_private =
       int_list_to_bytes
         [ 224; 114; 26; 212; 195; 244; 59; 190; 172; 168; 61; 43; 199; 150; 127
         ; 38; 231; 253; 83; 239; 77; 53; 17; 129; 247; 46; 198; 121; 147; 242
         ; 95; 99 ]
       |> Crypto.Secret.of_bytes in
     let dev1_static_public =
       int_list_to_bytes
         [ 164; 241; 106; 150; 20; 255; 195; 182; 223; 236; 37; 135; 126; 101
         ; 187; 255; 211; 191; 16; 19; 15; 134; 234; 31; 252; 52; 138; 62; 88
         ; 14; 120; 36 ]
       |> Crypto.Public.of_bytes in
     let dev2_static_private =
       int_list_to_bytes
         [ 56; 63; 223; 191; 65; 76; 161; 98; 187; 219; 126; 199; 86; 23; 147
         ; 194; 204; 57; 156; 82; 225; 132; 10; 140; 254; 102; 97; 25; 91; 249
         ; 140; 127 ]
       |> Crypto.Secret.of_bytes in
     let dev2_static_public =
       int_list_to_bytes
         [ 178; 147; 147; 105; 114; 57; 113; 157; 55; 78; 29; 91; 95; 80; 71; 23
         ; 132; 248; 26; 37; 211; 31; 233; 77; 185; 132; 60; 141; 237; 179; 140
         ; 53 ]
       |> Crypto.Public.of_bytes in
     (* local and remote ephemeral keys *)
     let dev1_ephemeral_private =
       int_list_to_bytes
         [ 224; 128; 105; 132; 216; 1; 207; 234; 117; 21; 175; 45; 37; 11; 107
         ; 251; 152; 90; 145; 131; 204; 95; 117; 155; 91; 5; 94; 149; 249; 4
         ; 247; 70 ]
       |> Crypto.Secret.of_bytes in
     let dev1_ephemeral_public =
       int_list_to_bytes
         [ 85; 135; 231; 208; 15; 35; 21; 225; 55; 108; 126; 159; 20; 213; 11
         ; 46; 95; 135; 236; 74; 31; 99; 68; 254; 82; 159; 148; 217; 233; 79
         ; 83; 118 ]
       |> Crypto.Public.of_bytes in
     let dev2_ephemeral_private =
       int_list_to_bytes
         [ 80; 9; 108; 30; 226; 174; 138; 236; 151; 228; 202; 108; 93; 98; 246
         ; 194; 113; 195; 125; 36; 126; 70; 193; 172; 144; 191; 209; 249; 221
         ; 188; 199; 98 ]
       |> Crypto.Secret.of_bytes in
     let dev2_ephemeral_public =
       int_list_to_bytes
         [ 15; 210; 28; 84; 230; 108; 56; 68; 19; 52; 180; 101; 114; 37; 13; 99
         ; 224; 79; 227; 122; 85; 100; 224; 195; 22; 64; 247; 160; 65; 149; 57
         ; 49 ]
       |> Crypto.Public.of_bytes in
     (* timestamp *)
     let timestamp =
       int_list_to_bytes [64; 0; 0; 0; 93; 102; 199; 171; 9; 0; 0; 0]
       |> Tai64n.of_bytes in
     let static_keypair1 =
       {secret= dev1_static_private; public= dev1_static_public} in
     let static_keypair2 =
       {secret= dev2_static_private; public= dev2_static_public} in
     let ephemeral_keypair1 =
       {secret= dev1_ephemeral_private; public= dev1_ephemeral_public} in
     let ephemeral_keypair2 =
       {secret= dev2_ephemeral_private; public= dev2_ephemeral_public} in
     let handshake1 : Handshake.t =
       let precomputed_static_static =
         Crypto.dh ~secret:static_keypair1.secret
           ~public:static_keypair2.public
         |> Or_error.ok_exn in
       { state= ref Handshake.Handshake_zeroed
       ; sequencer= Async.Throttle.Sequencer.create ()
       ; hash= Bytes.create 32
       ; chain_key= Shared.create_uninit ()
       ; preshared_key= Shared.of_bytes (Bytes.make 32 '\x00')
       ; local_ephemeral=
           {secret= Secret.create_uninit (); public= Public.create_uninit ()}
       ; local_index= ref Int32.zero
       ; remote_index= ref Int32.zero
       ; remote_static= static_keypair2.public
       ; remote_ephemeral= Public.create_uninit ()
       ; precomputed_static_static
       ; last_timestamp= ref Tai64n.epoch
       ; last_initiation_consumption= ref Tai64n.epoch
       ; last_sent_handshake= ref Tai64n.epoch } in
     let handshake2 : Handshake.t =
       let precomputed_static_static =
         Crypto.dh ~secret:static_keypair2.secret
           ~public:static_keypair1.public
         |> Or_error.ok_exn in
       { state= ref Handshake.Handshake_zeroed
       ; sequencer= Async.Throttle.Sequencer.create ()
       ; hash= Bytes.create 32
       ; chain_key= Shared.create_uninit ()
       ; preshared_key= Shared.of_bytes (Bytes.make 32 '\x00')
       ; local_ephemeral=
           {secret= Secret.create_uninit (); public= Public.create_uninit ()}
       ; local_index= ref Int32.zero
       ; remote_index= ref Int32.zero
       ; remote_static= static_keypair1.public
       ; remote_ephemeral= Public.create_uninit ()
       ; precomputed_static_static
       ; last_timestamp= ref Tai64n.epoch
       ; last_initiation_consumption= ref Tai64n.epoch
       ; last_sent_handshake= ref Tai64n.epoch } in
     let open Deferred.Or_error.Let_syntax in
     let%bind handshake_initiation =
       create_message_initiation ~local_ephemeral:ephemeral_keypair1 ~timestamp
         ~local_static_public:static_keypair1.public handshake1 in
     Messages.Handshake_initiation.hexdump_t_cstruct handshake_initiation ;
     let%bind peer1 =
       consume_message_initiation
       (* for testing only! should not be passed in in prod. *)
         ~peer:
           {handshake= handshake2; keypairs= ref (Keypair.create_empty_ts ())}
         ~msg:handshake_initiation ~local_static:static_keypair2 in
     let%bind handshake_response =
       create_message_response ~local_ephemeral:ephemeral_keypair2 peer1 in
     Messages.Handshake_response.hexdump_t_cstruct handshake_response ;
     let%bind peer2 =
       consume_message_response ~handshake:handshake1
         ~local_static:static_keypair1 handshake_response in
     print_string "chain_hash_1\n" ;
     pretty_print_bytes handshake1.hash ;
     print_string "chain_key_1\n" ;
     pretty_print_bytes (Shared.to_bytes handshake1.chain_key) ;
     print_string "chain_hash_2\n" ;
     pretty_print_bytes handshake2.hash ;
     print_string "chain_key_2\n" ;
     pretty_print_bytes (Shared.to_bytes handshake2.chain_key) ;
     let%bind () = begin_symmetric_session peer1 in
     let%bind () = begin_symmetric_session peer2 in
     Deferred.return (test_key_pairs peer1 peer2))
    |> Deferred.Or_error.ok_exn in
  [%expect
    {|
  t = {
    msg_type = 0x1
    sender = 0x3
    ephemeral = <buffer uint8_t[32] ephemeral>
  55 87 e7 d0 0f 23 15 e1  37 6c 7e 9f 14 d5 0b 2e
  5f 87 ec 4a 1f 63 44 fe  52 9f 94 d9 e9 4f 53 76

    signed_static = <buffer uint8_t[48] signed_static>
  e1 26 a3 99 20 6a ee 1a  a7 bc 39 a8 0b 4d 89 9c
  85 f7 df 4b 91 a3 fc 1b  71 5b c4 d8 cb 65 7b db
  86 51 42 4c 97 88 c4 e6  7a 1d e7 26 ed 7c 70 15

    signed_timestamp = <buffer uint8_t[28] signed_timestamp>
  3f e9 71 7f 93 7a f1 91  e0 62 fc a9 80 dc 9c d8
  20 c3 76 a5 11 80 f3 3e  a9 85 33 c5
    mac1 = <buffer uint8_t[32] mac1>
  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00

    mac2 = <buffer uint8_t[32] mac2>
  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00


  }
  t = {
    msg_type = 0x2
    sender = 0x0
    receiver = 0x3
    ephemeral = <buffer uint8_t[32] ephemeral>
  0f d2 1c 54 e6 6c 38 44  13 34 b4 65 72 25 0d 63
  e0 4f e3 7a 55 64 e0 c3  16 40 f7 a0 41 95 39 31

    signed_empty = <buffer uint8_t[16] signed_empty>
  8b 0e 1d 50 50 2e 9c b1  cb 45 53 6a c6 7b 05 b9

    mac1 = <buffer uint8_t[32] mac1>
  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00

    mac2 = <buffer uint8_t[32] mac2>
  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00


  }
  chain_hash_1

  b6 c3 dc a9 8a 6d e5 8e  25 dc f2 aa 1a c8 64 6c
  6e 78 a7 c4 e7 e2 79 43  f2 58 c5 40 41 ea 36 e1

  chain_key_1

  8d ec c9 b9 16 3e 68 e9  cd 3c 98 92 73 5f cc 7c
  ac 60 02 ff bb af 6f 85  6f bf 7c 1b ad c3 71 19

  chain_hash_2

  b6 c3 dc a9 8a 6d e5 8e  25 dc f2 aa 1a c8 64 6c
  6e 78 a7 c4 e7 e2 79 43  f2 58 c5 40 41 ea 36 e1

  chain_key_2

  8d ec c9 b9 16 3e 68 e9  cd 3c 98 92 73 5f cc 7c
  ac 60 02 ff bb af 6f 85  6f bf 7c 1b ad c3 71 19
     |}]

let%expect_test "test_handshake" =
  Crypto.init () |> Or_error.ok_exn ;
  let open Deferred.Let_syntax in
  (* local and remote static keys *)
  let%bind () =
    (let open Deferred.Or_error.Let_syntax in
    let static_keypair1 = Crypto.generate () |> Or_error.ok_exn in
    let static_keypair2 = Crypto.generate () |> Or_error.ok_exn in
    let handshake1 : Handshake.t =
      let precomputed_static_static =
        Crypto.dh ~secret:static_keypair1.secret ~public:static_keypair2.public
        |> Or_error.ok_exn in
      { state= ref Handshake.Handshake_zeroed
      ; sequencer= Async.Throttle.Sequencer.create ()
      ; hash= Bytes.create 32
      ; chain_key= Shared.create_uninit ()
      ; preshared_key= Shared.of_bytes (Bytes.make 32 '\x00')
      ; local_ephemeral=
          {secret= Secret.create_uninit (); public= Public.create_uninit ()}
      ; local_index= ref Int32.zero
      ; remote_index= ref Int32.zero
      ; remote_static= static_keypair2.public
      ; remote_ephemeral= Public.create_uninit ()
      ; precomputed_static_static
      ; last_timestamp= ref Tai64n.epoch
      ; last_initiation_consumption= ref Tai64n.epoch
      ; last_sent_handshake= ref Tai64n.epoch } in
    let handshake2 : Handshake.t =
      let precomputed_static_static =
        Crypto.dh ~secret:static_keypair2.secret ~public:static_keypair1.public
        |> Or_error.ok_exn in
      { state= ref Handshake.Handshake_zeroed
      ; sequencer= Async.Throttle.Sequencer.create ()
      ; hash= Bytes.create 32
      ; chain_key= Shared.create_uninit ()
      ; preshared_key= Shared.of_bytes (Bytes.make 32 '\x00')
      ; local_ephemeral=
          {secret= Secret.create_uninit (); public= Public.create_uninit ()}
      ; local_index= ref Int32.zero
      ; remote_index= ref Int32.zero
      ; remote_static= static_keypair1.public
      ; remote_ephemeral= Public.create_uninit ()
      ; precomputed_static_static
      ; last_timestamp= ref Tai64n.epoch
      ; last_initiation_consumption= ref Tai64n.epoch
      ; last_sent_handshake= ref Tai64n.epoch } in
    let%bind handshake_initiation =
      create_message_initiation ~local_static_public:static_keypair1.public
        handshake1 in
    let%bind peer1 =
      consume_message_initiation
      (* for testing only! should not be passed in in prod. *)
        ~peer:
          {handshake= handshake2; keypairs= ref (Keypair.create_empty_ts ())}
        ~msg:handshake_initiation ~local_static:static_keypair2 in
    let%bind handshake_response = create_message_response peer1 in
    let%bind peer2 =
      consume_message_response ~local_static:static_keypair1
        ~handshake:handshake1 handshake_response in
    if not (Bytes.equal handshake1.hash handshake2.hash) then
      failwith "chain hashes don't match" ;
    if not (Crypto.Shared.equals handshake1.chain_key handshake2.chain_key)
    then failwith "chain keys don't match" ;
    let%bind () = begin_symmetric_session peer1 in
    let%bind () = begin_symmetric_session peer2 in
    Deferred.return (test_key_pairs peer1 peer2))
    |> Deferred.Or_error.ok_exn in
  [%expect {|  |}]
