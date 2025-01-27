const std = @import("std");
const testing = std.testing;

// ----------------------------------- ERROR DEFINITIONS -----------------------------------  //

pub const MessageLengthLimitExceeded = error.MessageLengthLimitExceeded;

// ----------------------------------- SHA CONSTANTS -----------------------------------  //

//pub const ShaAlgorithm = enum { Sha1, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256 };

const SHA_1_DIGEST_LENGTH = 160 / 8;
const SHA_224_DIGEST_LENGTH = 224 / 8;
const SHA_256_DIGEST_LENGTH = 256 / 8;
const SHA_384_DIGEST_LENGTH = 384 / 8;
const SHA_512_DIGEST_LENGTH = 512 / 8;
const SHA_512_224_DIGEST_LENGTH = 224 / 8;
const SHA_512_256_DIGEST_LENGTH = 256 / 8;

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
    message_length: u64,
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
    message_length: u64,

    t_is_224: bool,
};

const Sha3Ctx = struct {
    const BLOCK_SIZE = 1024 / 8;

    message_schedule: [16]u64,
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
    message_length: u128,

    // I could generalize this in the future, like decribed in the standard.
    t_is_224: bool,
    t_is_256: bool,
    t_is_384: bool,
};

pub fn sha1_new() Sha1Ctx {
    var ctx = Sha1Ctx{
        .message_schedule = undefined,
        .hash = undefined,
        .a = undefined,
        .b = undefined,
        .c = undefined,
        .d = undefined,
        .e = undefined,
        .message_buffer = undefined,
        .message_length = 0,
    };

    @memcpy(&ctx.hash, &SHA_1_IV);
    ctx.a = ctx.hash[0];
    ctx.b = ctx.hash[1];
    ctx.c = ctx.hash[2];
    ctx.d = ctx.hash[3];
    ctx.e = ctx.hash[4];

    return ctx;
}

pub fn sha1_update(ctx: *Sha1Ctx, message: []const u8) !void {
    // TODO
    _ = .{ ctx, message };
}

pub fn sha1_final(ctx: *Sha1Ctx, out: [SHA_1_DIGEST_LENGTH]u8) void {
    // TODO
    _ = .{ ctx, out };
}

pub fn sha2_new(t: comptime_int) Sha2Ctx {
    if (comptime t != 224 and t != 256)
        @compileError("SHA-2 context can only be initialized in 224-bit and 256-bit mode.");

    var ctx = Sha2Ctx{
        .message_schedule = undefined,
        .hash = undefined,
        .a = if (t == 224) SHA_224_IV[0] else SHA_256_IV[0],
        .b = if (t == 224) SHA_224_IV[1] else SHA_256_IV[1],
        .c = if (t == 224) SHA_224_IV[2] else SHA_256_IV[2],
        .d = if (t == 224) SHA_224_IV[3] else SHA_256_IV[3],
        .e = if (t == 224) SHA_224_IV[4] else SHA_256_IV[4],
        .f = if (t == 224) SHA_224_IV[5] else SHA_256_IV[5],
        .g = if (t == 224) SHA_224_IV[6] else SHA_256_IV[6],
        .h = if (t == 224) SHA_224_IV[7] else SHA_256_IV[7],
        .message_buffer = undefined,
        .message_length = 0,
        .t_is_224 = (t == 224),
    };
    @memcpy(&ctx.hash, if (t == 224) &SHA_224_IV else &SHA_256_IV);

    return ctx;
}

pub fn sha224_new() Sha2Ctx {
    return sha2_new(224);
}

pub fn sha224_update(ctx: *Sha2Ctx, message: []const u8) !void {
    // TODO
    _ = .{ ctx, message };
}

pub fn sha224_final(ctx: *Sha1Ctx, out: [SHA_224_DIGEST_LENGTH]u8) void {
    // TODO
    _ = .{ ctx, out };
}

pub fn sha256_new() Sha2Ctx {
    return sha2_new(256);
}

pub fn sha256_update(ctx: *Sha2Ctx, message: []const u8) !void {
    // TODO
    _ = .{ ctx, message };
}

pub fn sha256_final(ctx: *Sha2Ctx, out: [SHA_256_DIGEST_LENGTH]u8) void {
    // TODO
    _ = .{ ctx, out };
}

pub fn sha3_new(t: comptime_int) Sha3Ctx {
    if (comptime t != 224 and t != 256 and t != 384 and t != 512)
        @compileError("SHA-3 context can only be initialized in 224, 256, 384 and 512-bit mode.");

    const iv: *const [Sha3Ctx.BLOCK_SIZE]u64 = switch (t) {
        224 => &SHA_512_224_IV,
        256 => &SHA_512_256_IV,
        384 => &SHA_384_IV,
        512 => &SHA_512_IV,
        _ => unreachable,
    };

    var ctx = Sha3Ctx{
        .message_schedule = undefined,
        .hash = undefined,
        .a = iv[0],
        .b = iv[1],
        .c = iv[2],
        .d = iv[3],
        .e = iv[4],
        .f = iv[5],
        .g = iv[6],
        .h = iv[7],
        .message_buffer = undefined,
        .message_length = 0,
        .t_is_224 = (t == 224),
        .t_is_256 = (t == 256),
        .t_is_384 = (t == 384),
    };
    @memcpy(&ctx.hash, iv);

    return ctx;
}

pub fn sha384_new() Sha3Ctx {
    return sha3_new(384);
}

pub fn sha384_update(ctx: *Sha3Ctx, message: []const u8) !void {
    // TODO
    _ = .{ ctx, message };
}

pub fn sha384_final(ctx: *Sha3Ctx, out: [SHA_384_DIGEST_LENGTH]u8) void {
    // TODO
    _ = .{ ctx, out };
}

pub fn sha512_new() Sha3Ctx {
    return sha3_new(512);
}

pub fn sha512_update(ctx: *Sha3Ctx, message: []const u8) !void {
    // TODO
    _ = .{ ctx, message };
}

pub fn sha512_final(ctx: *Sha3Ctx, out: [SHA_512_DIGEST_LENGTH]u8) void {
    // TODO
    _ = .{ ctx, out };
}

pub fn sha512_224_new() Sha3Ctx {
    return sha3_new(224);
}

pub fn sha512_224_update(ctx: *Sha3Ctx, message: []const u8) !void {
    // TODO
    _ = .{ ctx, message };
}

pub fn sha512_224_final(ctx: *Sha3Ctx, out: [SHA_512_224_DIGEST_LENGTH]u8) void {
    // TODO
    _ = .{ ctx, out };
}

pub fn sha512_256_new() Sha3Ctx {
    return sha3_new(256);
}

pub fn sha512_256_update(ctx: *Sha3Ctx, message: []const u8) !void {
    // TODO
    _ = .{ ctx, message };
}

pub fn sha512_256_final(ctx: *Sha3Ctx, out: [SHA_512_256_DIGEST_LENGTH]u8) void {
    // TODO
    _ = .{ ctx, out };
}
