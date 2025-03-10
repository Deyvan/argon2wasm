# Argon2 wasm version
## Usage

```ts
import { argon2, Argon2Types, Argon2Versions } from "argon2wasm"

let password = "a123123123"
let salt = "13djskjdskj12123"
let timeCost = 10
let memCost = 1024
let lanes = 10
let hashLen = 10

let hash = await argon2(password, salt, timeCost, memCost, lanes, hashLen, Argon2Versions.Ver1_3, Argon2Types.D)
console.log(hash.toString("hex")) // 31ef29d11c3f6ca7401b
```
