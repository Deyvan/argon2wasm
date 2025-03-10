import { Buffer } from "buffer"

export const Argon2Versions = {
    Ver1_0: 0x10,
    Ver1_3: 0x13
}

export const Argon2Types = {
    D: 0,
    I: 1,
    DI: 2
}

const ObjectErrors = {
    [-1]: "ARGON2_OUTPUT_PTR_NULL",
    [-2]: "ARGON2_OUTPUT_TOO_SHORT",
    [-3]: "ARGON2_OUTPUT_TOO_LONG",
    [-4]: "ARGON2_PWD_TOO_SHORT",
    [-5]: "ARGON2_PWD_TOO_LONG",
    [-6]: "ARGON2_SALT_TOO_SHORT",
    [-7]: "ARGON2_SALT_TOO_LONG",
    [-8]: "ARGON2_AD_TOO_SHORT",
    [-9]: "ARGON2_AD_TOO_LONG",
    [-10]: "ARGON2_SECRET_TOO_SHORT",
    [-11]: "ARGON2_SECRET_TOO_LONG",
    [-12]: "ARGON2_TIME_TOO_SMALL",
    [-13]: "ARGON2_TIME_TOO_LARGE",
    [-14]: "ARGON2_MEMORY_TOO_LITTLE",
    [-15]: "ARGON2_MEMORY_TOO_MUCH",
    [-16]: "ARGON2_LANES_TOO_FEW",
    [-17]: "ARGON2_LANES_TOO_MANY",
    [-18]: "ARGON2_PWD_PTR_MISMATCH",
    [-19]: "ARGON2_SALT_PTR_MISMATCH",
    [-20]: "ARGON2_SECRET_PTR_MISMATCH",
    [-21]: "ARGON2_AD_PTR_MISMATCH",
    [-22]: "ARGON2_MEMORY_ALLOCATION_ERROR",
    [-23]: "ARGON2_FREE_MEMORY_CBK_NULL",
    [-24]: "ARGON2_ALLOCATE_MEMORY_CBK_NULL",
    [-25]: "ARGON2_INCORRECT_PARAMETER",
    [-26]: "ARGON2_INCORRECT_TYPE",
    [-27]: "ARGON2_OUT_PTR_MISMATCH",
    [-28]: "ARGON2_THREADS_TOO_FEW",
    [-29]: "ARGON2_THREADS_TOO_MANY",
    [-30]: "ARGON2_MISSING_ARGS",
    [-31]: "ARGON2_ENCODING_FAIL",
    [-32]: "ARGON2_DECODING_FAIL",
    [-33]: "ARGON2_THREAD_FAIL",
    [-34]: "ARGON2_DECODING_LENGTH_FAIL",
    [-35]: "ARGON2_VERIFY_MISMATCH",
}

export async function argon2(password, salt, timeCost, memCost, lanes, hashLen, version, type){

    let m = await (await import("./argon2")).default()

    let passwordBuff = Buffer.from(password)
    let saltBuff = Buffer.from(salt)

    let passowrdOffset = m._malloc(passwordBuff.byteLength)
    let saltOffset = m._malloc(saltBuff.byteLength)
    let hashOffset = m._malloc(hashLen)

    let passwordMem = new Uint8Array(m.HEAP8.buffer, passowrdOffset, passwordBuff.byteLength)
    let saltMem = new Uint8Array(m.HEAP8.buffer, saltOffset, saltBuff.byteLength)

    passwordMem.set(passwordBuff)
    saltMem.set(saltBuff)

    let ret = m.argon2(
        timeCost, memCost, lanes, 
        passowrdOffset, passwordBuff.byteLength,
        saltOffset, saltBuff.byteLength, 
        hashOffset, hashLen, 
        type, version
    )

    if(ret != 0){
        m._free(passowrdOffset)
        m._free(saltOffset)
        m._free(hashOffset)
        throw new Error(ObjectErrors[ret])
    }

    m._free(passowrdOffset)
    m._free(saltOffset)
    m._free(hashOffset)

    return Buffer.from(new Uint8Array(m.HEAP8.buffer, hashOffset, hashLen))
}