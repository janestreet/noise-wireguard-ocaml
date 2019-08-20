open Core
open Key

val hash : bytes -> bytes Or_error.t
val hash2 : bytes -> bytes -> bytes Or_error.t
val mac : input:bytes -> key:Shared.key -> bytes Or_error.t
val hmac : input:bytes -> key:Shared.key -> bytes
