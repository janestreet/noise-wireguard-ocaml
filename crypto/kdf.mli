open Key

val kdf_1 : key:Shared.key -> bytes -> Shared.key
val kdf_2 : key:Shared.key -> bytes -> Shared.key * Shared.key
val kdf_3 : key:Shared.key -> bytes -> Shared.key * Shared.key * Shared.key
