const std = @import("std");
const testing = std.testing;

// ----------------------------------- ERROR DEFINITIONS -----------------------------------  //

pub const MessageLengthLimitExceeded = error.MessageLengthLimitExceeded;

// ----------------------------------- SHA CONSTANTS -----------------------------------  //

pub const ShaAlgorithm = enum { Sha1, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256 };

const SHA_1_IV = [_]u32{
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
};
const SHA_224_IV = [_]u32{
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
};
const SHA_256_IV = [_]u32{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};
const SHA_384_IV = [_]u64{
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
};
const SHA_512_IV = [_]u64{
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
};
const SHA_512_224_IV = [_]u64{
    0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF,
    0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1,
};
const SHA_512_256_IV = [_]u64{
    0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD,
    0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2,
};

// ----------------------------------- SHA ALGORITHMS -----------------------------------  //

const Sha1Ctx = struct {
    const BLOCK_SIZE = 512 / 8;

    message_schedule: [16]u32,
    hash: [5]u32,
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,

    message_buffer: [BLOCK_SIZE]u8,
    buffer_index: u6,
};

const Sha2Ctx = struct {
    const BLOCK_SIZE = 512 / 8;

    message_schedule: [16]u32,
    hash: [8]u32,
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,
    f: u32,
    g: u32,
    h: u32,

    message_buffer: [BLOCK_SIZE]u8,
    buffer_index: u6,

    t_is_224: bool,
};

const Sha3Ctx = struct {
    const BLOCK_SIZE = 1024 / 8;

    message_schedule: [16]u32,
    hash: [8]u64,
    a: u64,
    b: u64,
    c: u64,
    d: u64,
    e: u64,
    f: u64,
    g: u64,
    h: u64,

    message_buffer: [BLOCK_SIZE]u8,
    buffer_index: u7,

    // could be generalized in the future, like decribed in the standard
    t_is_224: bool,
    t_is_256: bool,
    t_is_384: bool,
};
