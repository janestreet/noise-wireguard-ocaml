open! Core

external init_ : unit -> int = "caml_sodium_init"

(* TODO: handle wiping secrets *)

let init () =
  let init_val = init_ () in
  if init_val < 0 then
    Or_error.error_s [%message "could not initialize sodium." (init_val : int)]
  else Or_error.return ()
