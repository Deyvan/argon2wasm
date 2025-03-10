
export enum Argon2Versions {
    Ver1_0 = 0x10,
    Ver1_3 = 0x13
}

export enum Argon2Types {
    D = 0,
    I = 1,
    DI = 2
}

export async function argon2(password: any, salt: any, timeCost: number, memCost: number, lanes: number, hashLen: number, version: Argon2Versions, type: Argon2Types): Promise<Buffer>