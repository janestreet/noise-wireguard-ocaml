open Core
open Key

val generate : unit -> keypair Or_error.t
val dh : public:Public.key -> secret:Secret.key -> Shared.key Or_error.t
