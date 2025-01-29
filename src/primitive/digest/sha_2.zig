const std = @import("std");
const testing = std.testing;

const sha = @import("./sha_core.zig");

const builtin = @import("builtin");
const dbg = builtin.mode == std.builtin.Mode.Debug;

pub const SHA_224_DIGEST_LENGTH = 224 / 8;
pub const SHA_224_MESSAGE_BITS_LIMIT = 1 << 64;

pub const SHA_256_DIGEST_LENGTH = 256 / 8;
pub const SHA_256_MESSAGE_BITS_LIMIT = 1 << 64;

pub const SHA_384_DIGEST_LENGTH = 384 / 8;
pub const SHA_384_MESSAGE_BITS_LIMIT = 1 << 128;

pub const SHA_512_DIGEST_LENGTH = 512 / 8;
pub const SHA_512_MESSAGE_BITS_LIMIT = 1 << 128;

pub const SHA_512_224_DIGEST_LENGTH = 224 / 8;
pub const SHA_512_224_MESSAGE_BITS_LIMIT = 1 << 128;

pub const SHA_512_256_DIGEST_LENGTH = 256 / 8;
pub const SHA_512_256_MESSAGE_BITS_LIMIT = 1 << 128;

pub const Sha256Ctx = struct {
    pub const BLOCK_SIZE = 512 / 8;
    pub const MESSAGE_SCHEDULE_WORDS = 64;
    pub const WordType = u32;

    hash: [SHA_256_DIGEST_LENGTH / @sizeOf(WordType)]WordType,
    message_buffer: [BLOCK_SIZE]u8,
    message_length: u64,

    t_is_224: bool,
};

pub const Sha512Ctx = struct {
    pub const BLOCK_SIZE = 1024 / 8;
    pub const MESSAGE_SCHEDULE_WORDS = 80;
    pub const WordType = u64;

    hash: [SHA_512_DIGEST_LENGTH / @sizeOf(WordType)]WordType,
    message_buffer: [BLOCK_SIZE]u8,
    message_length: u128,

    // I may generalize this in the future, like decribed in the standard.
    t_is_224: bool,
    t_is_256: bool,
    t_is_384: bool,
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

fn sha256_context_new(t: comptime_int) Sha256Ctx {
    if (comptime t != 224 and t != 256)
        @compileError("SHA-2 context can only be initialized in 224-bit and 256-bit mode.");

    var ctx = Sha256Ctx{
        .hash = undefined,
        .message_buffer = undefined,
        .message_length = 0,
        .t_is_224 = (t == 224),
    };
    @memcpy(&ctx.hash, if (t == 224) &SHA_224_IV else &SHA_256_IV);

    return ctx;
}

fn sha256_context_update(ctx: *Sha256Ctx, message: []const u8) !void {
    // All variants of SHA-2 can digest a message of a maximum length of (2^64 - 1) bits
    // due to the nature of its padding (which is identical to SHA-1).
    return sha.generic_update(
        Sha256Ctx,
        1 << 64,
        &sha256_compress_block,
        ctx,
        message,
    );
}

fn sha256_context_final(ctx: *Sha256Ctx, digest_length: comptime_int, out: *[digest_length]u8) void {
    return sha.generic_final(
        Sha256Ctx,
        Sha256Ctx.WordType,
        u64,
        digest_length,
        &sha256_compress_block,
        ctx,
        out,
    );
}

fn sha256_compress_block(ctx: *Sha256Ctx) void {
    // Prepare the message schedule.
    var message_schedule: [Sha256Ctx.MESSAGE_SCHEDULE_WORDS]u32 = undefined;

    for (0..Sha256Ctx.BLOCK_SIZE / @sizeOf(Sha256Ctx.WordType)) |t|
        message_schedule[t] = sha.deserialize_int_big_endian(
            Sha256Ctx.WordType,
            @ptrCast(ctx.message_buffer[(t * @sizeOf(Sha256Ctx.WordType))..((t + 1) * @sizeOf(Sha256Ctx.WordType))]),
        );
    for (Sha256Ctx.BLOCK_SIZE / @sizeOf(Sha256Ctx.WordType)..Sha256Ctx.MESSAGE_SCHEDULE_WORDS) |t| {
        message_schedule[t] = sha2_sigma_256_1(message_schedule[t - 2]) +% message_schedule[t - 7] +% sha2_sigma_256_0(message_schedule[t - 15]) +% message_schedule[t - 16];
    }

    // Initialize working variables.
    var a = ctx.hash[0];
    var b = ctx.hash[1];
    var c = ctx.hash[2];
    var d = ctx.hash[3];
    var e = ctx.hash[4];
    var f = ctx.hash[5];
    var g = ctx.hash[6];
    var h = ctx.hash[7];

    // Perform the actual hashing.
    inline for (0..Sha256Ctx.MESSAGE_SCHEDULE_WORDS) |t| {
        const tmp1 = h +% sha2_Sigma_256_1(e) +% sha.ch(Sha256Ctx.WordType, e, f, g) +% SHA2_K_256[t] +% message_schedule[t];
        const tmp2 = sha2_Sigma_256_0(a) +% sha.maj(Sha256Ctx.WordType, a, b, c);
        h = g;
        g = f;
        f = e;
        e = d +% tmp1;
        d = c;
        c = b;
        b = a;
        a = tmp1 +% tmp2;
    }

    // Add the result to the previous hash state.
    ctx.hash[0] +%= a;
    ctx.hash[1] +%= b;
    ctx.hash[2] +%= c;
    ctx.hash[3] +%= d;
    ctx.hash[4] +%= e;
    ctx.hash[5] +%= f;
    ctx.hash[6] +%= g;
    ctx.hash[7] +%= h;
}

const SHA2_K_256 = [Sha256Ctx.MESSAGE_SCHEDULE_WORDS]u32{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

fn sha2_Sigma_256_0(x: u32) u32 {
    return sha.rotr(u32, x, 2) ^ sha.rotr(u32, x, 13) ^ sha.rotr(u32, x, 22);
}

fn sha2_Sigma_256_1(x: u32) u32 {
    return sha.rotr(u32, x, 6) ^ sha.rotr(u32, x, 11) ^ sha.rotr(u32, x, 25);
}

fn sha2_sigma_256_0(x: u32) u32 {
    return sha.rotr(u32, x, 7) ^ sha.rotr(u32, x, 18) ^ sha.shr(u32, x, 3);
}

fn sha2_sigma_256_1(x: u32) u32 {
    return sha.rotr(u32, x, 17) ^ sha.rotr(u32, x, 19) ^ sha.shr(u32, x, 10);
}

pub fn sha224_new() Sha256Ctx {
    return sha256_context_new(224);
}

pub fn sha224_update(ctx: *Sha256Ctx, message: []const u8) !void {
    if (dbg and !ctx.t_is_224)
        @panic("Debug: Attempt to call sha224_update on a SHA-256 context.");
    return sha256_context_update(ctx, message);
}

pub fn sha224_final(ctx: *Sha256Ctx, out: *[SHA_224_DIGEST_LENGTH]u8) void {
    if (dbg and !ctx.t_is_224)
        @panic("Debug: Attempt to call sha224_final on a SHA-256 context.");
    return sha256_context_final(ctx, SHA_224_DIGEST_LENGTH, out);
}

pub fn sha256_new() Sha256Ctx {
    return sha256_context_new(256);
}

pub fn sha256_update(ctx: *Sha256Ctx, message: []const u8) !void {
    if (dbg and ctx.t_is_224)
        @panic("Debug: Attempt to call sha256_update on a SHA-224 context.");
    return sha256_context_update(ctx, message);
}

pub fn sha256_final(ctx: *Sha256Ctx, out: *[SHA_256_DIGEST_LENGTH]u8) void {
    if (dbg and ctx.t_is_224)
        @panic("Debug: Attempt to call sha256_final on a SHA-224 context.");
    return sha256_context_final(ctx, SHA_256_DIGEST_LENGTH, out);
}

fn sha512_context_new(t: comptime_int) Sha512Ctx {
    const iv: *const [SHA_512_DIGEST_LENGTH / @sizeOf(Sha512Ctx.WordType)]Sha512Ctx.WordType = switch (t) {
        224 => &SHA_512_224_IV,
        256 => &SHA_512_256_IV,
        384 => &SHA_384_IV,
        512 => &SHA_512_IV,
        else => @compileError(
            "SHA-3 context can currently only be initialized in 384, 512, 512/224 and 512/256 mode.",
        ),
    };

    var ctx = Sha512Ctx{
        .hash = undefined,
        .message_buffer = undefined,
        .message_length = 0,
        .t_is_224 = (t == 224),
        .t_is_256 = (t == 256),
        .t_is_384 = (t == 384),
    };
    @memcpy(&ctx.hash, iv);

    return ctx;
}

fn sha512_context_update(ctx: *Sha512Ctx, message: []const u8) !void {
    return sha.generic_update(
        Sha512Ctx,
        1 << 128,
        &sha512_compress_block,
        ctx,
        message,
    );
}

fn sha512_context_final(ctx: *Sha512Ctx, digest_length: comptime_int, out: *[digest_length]u8) void {
    return sha.generic_final(
        Sha512Ctx,
        Sha512Ctx.WordType,
        u128,
        digest_length,
        &sha512_compress_block,
        ctx,
        out,
    );
}

fn sha512_compress_block(ctx: *Sha512Ctx) void {
    // Prepare the message schedule.
    var message_schedule: [Sha512Ctx.MESSAGE_SCHEDULE_WORDS]u64 = undefined;

    for (0..Sha512Ctx.BLOCK_SIZE / @sizeOf(Sha512Ctx.WordType)) |t|
        message_schedule[t] = sha.deserialize_int_big_endian(
            Sha512Ctx.WordType,
            @ptrCast(ctx.message_buffer[(t * @sizeOf(Sha512Ctx.WordType))..((t + 1) * @sizeOf(Sha512Ctx.WordType))]),
        );
    for (Sha512Ctx.BLOCK_SIZE / @sizeOf(Sha512Ctx.WordType)..Sha512Ctx.MESSAGE_SCHEDULE_WORDS) |t| {
        message_schedule[t] = sha2_sigma_512_1(message_schedule[t - 2]) +% message_schedule[t - 7] +% sha2_sigma_512_0(message_schedule[t - 15]) +% message_schedule[t - 16];
    }

    // Initialize working variables.
    var a = ctx.hash[0];
    var b = ctx.hash[1];
    var c = ctx.hash[2];
    var d = ctx.hash[3];
    var e = ctx.hash[4];
    var f = ctx.hash[5];
    var g = ctx.hash[6];
    var h = ctx.hash[7];

    // Perform the actual hashing.
    inline for (0..Sha512Ctx.MESSAGE_SCHEDULE_WORDS) |t| {
        const tmp1 = h +% sha2_Sigma_512_1(e) +% sha.ch(Sha512Ctx.WordType, e, f, g) +% SHA2_K_512[t] +% message_schedule[t];
        const tmp2 = sha2_Sigma_512_0(a) +% sha.maj(Sha512Ctx.WordType, a, b, c);
        h = g;
        g = f;
        f = e;
        e = d +% tmp1;
        d = c;
        c = b;
        b = a;
        a = tmp1 +% tmp2;
    }

    // Add the result to the previous hash state.
    ctx.hash[0] +%= a;
    ctx.hash[1] +%= b;
    ctx.hash[2] +%= c;
    ctx.hash[3] +%= d;
    ctx.hash[4] +%= e;
    ctx.hash[5] +%= f;
    ctx.hash[6] +%= g;
    ctx.hash[7] +%= h;
}

const SHA2_K_512 = [Sha512Ctx.MESSAGE_SCHEDULE_WORDS]u64{
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
};

fn sha2_Sigma_512_0(x: u64) u64 {
    return sha.rotr(u64, x, 28) ^ sha.rotr(u64, x, 34) ^ sha.rotr(u64, x, 39);
}

fn sha2_Sigma_512_1(x: u64) u64 {
    return sha.rotr(u64, x, 14) ^ sha.rotr(u64, x, 18) ^ sha.rotr(u64, x, 41);
}

fn sha2_sigma_512_0(x: u64) u64 {
    return sha.rotr(u64, x, 1) ^ sha.rotr(u64, x, 8) ^ sha.shr(u64, x, 7);
}

fn sha2_sigma_512_1(x: u64) u64 {
    return sha.rotr(u64, x, 19) ^ sha.rotr(u64, x, 61) ^ sha.shr(u64, x, 6);
}

pub fn sha384_new() Sha512Ctx {
    return sha512_context_new(384);
}

pub fn sha384_update(ctx: *Sha512Ctx, message: []const u8) !void {
    if (dbg and !ctx.t_is_384)
        @panic("Debug: Attempt to call sha384_update on a SHA-2 context not initialized in 384-bit mode.");
    return sha512_context_update(ctx, message);
}

pub fn sha384_final(ctx: *Sha512Ctx, out: *[SHA_384_DIGEST_LENGTH]u8) void {
    if (dbg and !ctx.t_is_384)
        @panic("Debug: Attempt to call sha384_final on a SHA-2 context not initialized in 384-bit mode.");
    return sha512_context_final(ctx, SHA_384_DIGEST_LENGTH, out);
}

pub fn sha512_new() Sha512Ctx {
    return sha512_context_new(512);
}

pub fn sha512_update(ctx: *Sha512Ctx, message: []const u8) !void {
    if (dbg and (ctx.t_is_224 or ctx.t_is_256 or ctx.t_is_384))
        @panic("Debug: Attempt to call sha512_update on a SHA-2 context not initialized in 512-bit mode.");
    return sha512_context_update(ctx, message);
}

pub fn sha512_final(ctx: *Sha512Ctx, out: *[SHA_512_DIGEST_LENGTH]u8) void {
    if (dbg and (ctx.t_is_224 or ctx.t_is_256 or ctx.t_is_384))
        @panic("Debug: Attempt to call sha512_final on a SHA-2 context not initialized in 512-bit mode.");
    return sha512_context_final(ctx, SHA_512_DIGEST_LENGTH, out);
}

pub fn sha512_224_new() Sha512Ctx {
    return sha512_context_new(224);
}

pub fn sha512_224_update(ctx: *Sha512Ctx, message: []const u8) !void {
    if (dbg and !ctx.t_is_224)
        @panic("Debug: Attempt to call sha512_224_update on a SHA-2 context not initialized in 224-bit mode.");
    return sha512_context_update(ctx, message);
}

pub fn sha512_224_final(ctx: *Sha512Ctx, out: *[SHA_512_224_DIGEST_LENGTH]u8) void {
    if (dbg and !ctx.t_is_224)
        @panic("Debug: Attempt to call sha512_224_final on a SHA-2 context not initialized in 224-bit mode.");
    return sha512_context_final(ctx, SHA_512_224_DIGEST_LENGTH, out);
}

pub fn sha512_256_new() Sha512Ctx {
    return sha512_context_new(256);
}

pub fn sha512_256_update(ctx: *Sha512Ctx, message: []const u8) !void {
    if (dbg and !ctx.t_is_256)
        @panic("Debug: Attempt to call sha512_256_update on a SHA-2 context not initialized in 256-bit mode.");
    return sha512_context_update(ctx, message);
}

pub fn sha512_256_final(ctx: *Sha512Ctx, out: *[SHA_512_256_DIGEST_LENGTH]u8) void {
    if (dbg and !ctx.t_is_256)
        @panic("Debug: Attempt to call sha512_256_final on a SHA-2 context not initialized in 256-bit mode.");
    return sha512_context_final(ctx, SHA_512_256_DIGEST_LENGTH, out);
}

// https://www.di-mgt.com.au/sha_testvectors.html
test "SHA-224 basic test" {
    try sha.run_hash_precomputed_tests(
        Sha256Ctx,
        SHA_224_DIGEST_LENGTH,
        sha224_new,
        sha224_update,
        sha224_final,
        &.{
            .{ .message = "", .hash = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f" },
            .{ .message = "abc", .hash = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" },
            .{
                .message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                .hash = "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
            },
            .{
                .message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                .hash = "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3",
            },
        },
    );
}

test "SHA-224 padding test" {
    // Here we test every possible length of the message in the last block
    // to make sure that the padding is correct in every single case.

    // The following are the hashes of the ASCII strings '', 'a', 'aa', etc.
    // up until 63 (= [SHA-224 block size in bits] / 8 - 1) concatenated 'a's.
    const reference = [64]*const [2 * SHA_224_DIGEST_LENGTH]u8{ "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5", "2ef29e646f6de95de993a59eb1a94cbf52986892949a0abc015a01f7", "ed782653bfec275cf37d027511a68cece08d1e53df1360c762ce043a", "fb56e0a07d1d4ba4a73d42a07d671f65f96513dc12f9d25f2b5ee86e", "04c15392c64c3db52f9a7fcfb7c0c370900e0308007617899430d088", "2886915dd9dedb0ce015f500ffb570901a69a8357728f893eef45344", "b1de26e908098a9b462c11fdd577613d356a7ff06ddb42fda3ab002b", "57dde80cb5dd10cee89424d7d9d8c4fd7949c882da78110e660dec06", "be63cd48d0b068927261c401a33a386136911c3420a5c335e00599fd", "194c4c5045aee1019b77cb1be88ac68034eb2ddd5a8368054141a11f", "5fa4fb5daff0a9b069061839e5605caff0446465f82268775a226333", "85e4d4fcca88691c8008ce19bd9a3de6b9814dd055c8d21bfd4037bb", "da79142fa39f7f11b990aa9dc4994b6e9ce49454058d5423869acf4c", "bd3278d31dec829db380cfe7d7100fecb4b853f054684687f4c27717", "e541fff1289f562eff589da3c8358d91e4dd589bf5dcc37555eb84fe", "0e0a4176c0c6966926acc6fccd2febd418a407df26f76645139d1320", "d5f1096a707710cf5038ed370f7839543eaea0ed054c7484319e2f9c", "e3a0b5557f7894cbb18d6ed06268242212f098d61e179e80a5e96dbc", "fbb6819175a23811c01073f6142af14e80f2d0c598bed6649f307e1f", "43586eff52cbaf9f22482f34a9437ff45bd2e7312ad586b3dd82802f", "2b9d728b01e2c27a40c5fc27d51d5c93f6a160f0f25da8d924e2b570", "eb7ff45dd3d5871ffd6aee24400367cc835aa0d2311d46b2a48b0424", "ac4f39fb481df8f86b6ddf6e527e61893d259b49810416584b468d22", "c4da7f3f63b9da485b734a270f1af6d132b15f177e06445faec5586b", "91a67814117203c32cfc333869bc74f8c721c10672c3516042d88a0b", "7824f1cc7591643231cefe91bbf6fa88b233bf1e8229a59a2cd01c15", "735d169738ebd05edc44cc49a6a99352815cafec12c10d5bd27e8359", "919523d5847d1ee4f9d72f6bd86e3d1bfb785831237a9d580b87448c", "4c166aebdf561231f2b679d8e8457667c0f374043de76d8e7306cb49", "31723190cc4bc6ae686caeea44c54b7b50e30941b8dca3404fe180d8", "f9b67111fdab7e860d1dbe801efa9b75b563e0ee606a9cbabc1288b9", "37e7740b3af132a8edc5e1636817ce1625b831e0ffd47e5c93d4e3b8", "21093fb6a83a36a2b55afa76da42d66de4ebc3b99fb340739d068500", "62d7fcd624a2c1d674ead77584bd66e06d2a6ed160702a594dd6a26e", "507fba56abf0fe3856d0d61527d2a96b18e234bad594bdc969fbfdf4", "6d3a8a79bcc6222986f3b3f17b716774de66d321d51ec34e49995b18", "b622cd8b687970603662b70401a36e464f6860ad337be21c86f17dce", "9c63438f755166862211cc708592f918d31c24e7e70080d6d08e3685", "0126a8fdfaea25bb65fa0b8d6586cd64eee956369b5d2c814607e9f9", "47e263d6419979086bd9a8c4f93591cba373912b68e2ae86085bd2df", "7d8c659cacc50ffc474948b79d65ed98bdab16f6b8a511d184593c86", "da1619b92df1a450be79a14a21e270cb2257230f7dfdc61128e0b49e", "babea0fecfea0aa82d1580abca47dad191f5b9d5a51788d64f678393", "61dd4e5d414a5ae61e76a9b7524223f3cdaf7c9c02b73c175b3e03dd", "fc50179169329ce825404d027fdab44058efc9f28ccddd694a31960e", "b5b7bef9dba5e6a57cecdc03d9a539667f3ca131343de3b6763d7463", "58756e846cce4e08b2ae1103ec3dd2c5755c15f94c1127782dde82c5", "73e0009122e9f4d311459277b81009e9cecc4b3dccf785d4ad476a14", "c0af565a56aeccfd2d40455f20d2c9431a7ab88c61e94973c97cff91", "df427221dc453d5c1466081d9d6e9da3155d5d0dff2a90eb0425036c", "7820fc9fc80c5ed788738da53fbfa6cf1fa981d656a3bb1e68cdf281", "163a72bc0462179bf0486f8a139da514913670d12bbe1d84efc44556", "3fae7c2d692c1610c4a20a17a790d256c3b0071bcdf6fb7fb9538681", "282e1dec88fa36a1070631cca69e3c08a5e18e29fb0b6f6927fbcc0d", "fb0bd626a70c28541dfa781bb5cc4d7d7f56622a58f01a0b1ddd646f", "d40854fc9caf172067136f2e29e1380b14626bf6f0dd06779f820dcd", "b5d09534784ab6578128bce7f28a96a56e3b45c4f734f74739076249", "00df3f1eaa489fd28a9de6e6d7b55402c4e3a56928c5043d77240237", "a82137820aaae9e66f277c3a9254f4a6078c47b410bc9d9a761c2e0b", "efda4316fe2d457d622cf1fc42993d41566f77449b7494b38e250c41", "54e3b540f6792b6a4570f5225717686fbf670fd0dfd3802e4ace9d77", "0daa67402af98b9988c65471b2589dbcdd8bb39569ed77c592aca4a4", "1d4e051f4d6fed2a63fd2421e65834cec00d64456553de3496ae8b1d" };

    var digest_buffer: [SHA_224_DIGEST_LENGTH]u8 = undefined;
    for (0..64) |i| {
        var ctx = sha224_new();
        for (0..i) |_|
            try sha224_update(&ctx, "a");
        sha224_final(&ctx, &digest_buffer);

        const ref = sha.hex_to_bytes(SHA_224_DIGEST_LENGTH, reference[i]);
        try testing.expectEqualSlices(u8, ref[0..], digest_buffer[0..]);
    }
}

test "SHA-224 maximum length violation (simulated)" {
    var ctx = sha224_new();
    ctx.message_length = (1 << 61) - 1; // 2^64 - 8 bits
    try testing.expectError(sha.MessageLengthLimitExceeded, sha224_update(&ctx, "a"));
}

// https://www.di-mgt.com.au/sha_testvectors.html
test "SHA-256 basic test" {
    try sha.run_hash_precomputed_tests(
        Sha256Ctx,
        SHA_256_DIGEST_LENGTH,
        sha256_new,
        sha256_update,
        sha256_final,
        &.{
            .{ .message = "", .hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
            .{ .message = "abc", .hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
            .{
                .message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                .hash = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            },
            .{
                .message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                .hash = "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
            },
        },
    );
}

test "SHA-256 padding test" {
    // Here we test every possible length of the message in the last block
    // to make sure that the padding is correct in every single case.

    // The following are the hashes of the ASCII strings '', 'a', 'aa', etc.
    // up until 63 (= [SHA-256 block size in bits] / 8 - 1) concatenated 'a's.
    const reference = [64]*const [2 * SHA_256_DIGEST_LENGTH]u8{ "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", "961b6dd3ede3cb8ecbaacbd68de040cd78eb2ed5889130cceb4c49268ea4d506", "9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0", "61be55a8e2f6b4e172338bddf184d6dbee29c98853e0a0485ecee7f27b9af0b4", "ed968e840d10d2d313a870bc131a4e2c311d7ad09bdf32b3418147221f51a6e2", "ed02457b5c41d964dbd2f2a609d63fe1bb7528dbe55e1abf5b52c249cd735797", "e46240714b5db3a23eee60479a623efba4d633d27fe4f03c904b9e219a7fbe60", "1f3ce40415a2081fa3eee75fc39fff8e56c22270d1a978a7249b592dcebd20b4", "f2aca93b80cae681221f0445fa4e2cae8a1f9f8fa1e1741d9639caad222f537d", "bf2cb58a68f684d95a3b78ef8f661c9a4e5b09e82cc8f9cc88cce90528caeb27", "28cb017dfc99073aa1b47c1b30f413e3ce774c4991eb4158de50f9dbb36d8043", "f24abc34b13fade76e805799f71187da6cd90b9cac373ae65ed57f143bd664e5", "a689d786e81340e45511dec6c7ab2d978434e5db123362450fe10cfac70d19d0", "82cab7df0abfb9d95dca4e5937ce2968c798c726fea48c016bf9763221efda13", "ef2df0b539c6c23de0f4cbe42648c301ae0e22e887340a4599fb4ef4e2678e48", "0c0beacef8877bbf2416eb00f2b5dc96354e26dd1df5517320459b1236860f8c", "b860666ee2966dd8f903be44ee605c6e1366f926d9f17a8f49937d11624eb99d", "c926defaaa3d13eda2fc63a553bb7fb7326bece6e7cb67ca5296e4727d89bab4", "a0b4aaab8a966e2193ba172d68162c4656860197f256b5f45f0203397ff3f99c", "42492da06234ad0ac76f5d5debdb6d1ae027cffbe746a1c13b89bb8bc0139137", "7df8e299c834de198e264c3e374bc58ecd9382252a705c183beb02f275571e3b", "ec7c494df6d2a7ea36668d656e6b8979e33641bfea378c15038af3964db057a3", "897d3e95b65f26676081f8b9f3a98b6ee4424566303e8d4e7c7522ebae219eab", "09f61f8d9cd65e6a0c258087c485b6293541364e42bd97b2d7936580c8aa3c54", "2f521e2a7d0bd812cbc035f4ed6806eb8d851793b04ba147e8f66b72f5d1f20f", "9976d549a25115dab4e36d0c1fb8f31cb07da87dd83275977360eb7dc09e88de", "cc0616e61cbd6e8e5e34e9fb2d320f37de915820206f5696c31f1fbd24aa16de", "9c547cb8115a44883b9f70ba68f75117cd55359c92611875e386f8af98c172ab", "6913c9c7fd42fe23df8b6bcd4dbaf1c17748948d97f2980b432319c39eddcf6c", "3a54fc0cbc0b0ef48b6507b7788096235d10292dd3ae24e22f5aa062d4f9864a", "61c60b487d1a921e0bcc9bf853dda0fb159b30bf57b2e2d2c753b00be15b5a09", "3ba3f5f43b92602683c19aee62a20342b084dd5971ddd33808d81a328879a547", "852785c805c77e71a22340a54e9d95933ed49121e7d2bf3c2d358854bc1359ea", "a27c896c4859204843166af66f0e902b9c3b3ed6d2fd13d435abc020065c526f", "629362afc62c74497caed2272e30f8125ecd0965f8d8d7cfc4e260f7f8dd319d", "22c1d24bcd03e9aee9832efccd6da613fc702793178e5f12c945c7b67ddda933", "21ec055b38ce759cd4d0f477e9bdec2c5b8199945db4439bae334a964df6246c", "365a9c3e2c2af0a56e47a9dac51c2c5381bf8f41273bad3175e0e619126ad087", "b4d5e56e929ba4cda349e9274e3603d0be246b82016bca20f363963c5f2d6845", "e33cdf9c7f7120b98e8c78408953e07f2ecd183006b5606df349b4c212acf43e", "c0f8bd4dbc2b0c03107c1c37913f2a7501f521467f45dd0fef6958e9a4692719", "7a538607fdaab9296995929f451565bbb8142e1844117322aafd2b3d76b01aff", "66d34fba71f8f450f7e45598853e53bfc23bbd129027cbb131a2f4ffd7878cd0", "16849877c6c21ef0bfa68e4f6747300ddb171b170b9f00e189edc4c2fc4db93e", "52789e3423b72beeb898456a4f49662e46b0cbb960784c5ef4b1399d327e7c27", "6643110c5628fff59edf76d82d5bf573bf800f16a4d65dfb1e5d6f1a46296d0b", "11eaed932c6c6fddfc2efc394e609facf4abe814fc6180d03b14fce13a07d0e5", "97daac0ee9998dfcad6c9c0970da5ca411c86233a944c25b47566f6a7bc1ddd5", "8f9bec6a62dd28ebd36d1227745592de6658b36974a3bb98a4c582f683ea6c42", "160b4e433e384e05e537dc59b467f7cb2403f0214db15c5db58862a3f1156d2e", "bfc5fe0e360152ca98c50fab4ed7e3078c17debc2917740d5000913b686ca129", "6c1b3dc7a706b9dc81352a6716b9c666c608d8626272c64b914ab05572fc6e84", "abe346a7259fc90b4c27185419628e5e6af6466b1ae9b5446cac4bfc26cf05c4", "a3f01b6939256127582ac8ae9fb47a382a244680806a3f613a118851c1ca1d47", "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318", "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a", "f13b2d724659eb3bf47f2dd6af1accc87b81f09f59f2b75e5c0bed6589dfe8c6", "d5c039b748aa64665782974ec3dc3025c042edf54dcdc2b5de31385b094cb678", "111bb261277afd65f0744b247cd3e47d386d71563d0ed995517807d5ebd4fba3", "11ee391211c6256460b6ed375957fadd8061cafbb31daf967db875aebd5aaad4", "35d5fc17cfbbadd00f5e710ada39f194c5ad7c766ad67072245f1fad45f0f530", "f506898cc7c2e092f9eb9fadae7ba50383f5b46a2a4fe5597dbb553a78981268", "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34" };

    var digest_buffer: [SHA_256_DIGEST_LENGTH]u8 = undefined;
    for (0..64) |i| {
        var ctx = sha256_new();
        for (0..i) |_|
            try sha256_update(&ctx, "a");
        sha256_final(&ctx, &digest_buffer);

        const ref = sha.hex_to_bytes(SHA_256_DIGEST_LENGTH, reference[i]);
        try testing.expectEqualSlices(u8, ref[0..], digest_buffer[0..]);
    }
}

test "SHA-256 maximum length violation (simulated)" {
    var ctx = sha256_new();
    ctx.message_length = (1 << 61) - 1; // 2^64 - 8 bits
    try testing.expectError(sha.MessageLengthLimitExceeded, sha256_update(&ctx, "a"));
}

// https://www.di-mgt.com.au/sha_testvectors.html
test "SHA-512 basic test" {
    try sha.run_hash_precomputed_tests(
        Sha512Ctx,
        SHA_512_DIGEST_LENGTH,
        sha512_new,
        sha512_update,
        sha512_final,
        &.{
            .{ .message = "", .hash = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" },
            .{ .message = "abc", .hash = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
            .{
                .message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                .hash = "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
            },
            .{
                .message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                .hash = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
            },
        },
    );
}

test "SHA-512 padding test" {
    // Here we test every possible length of the message in the last block
    // to make sure that the padding is correct in every single case.

    // The following are the hashes of the ASCII strings '', 'a', 'aa', etc.
    // up until 127 (= [SHA-512 block size in bits] / 8 - 1) concatenated 'a's.
    const reference = [128]*const [2 * SHA_512_DIGEST_LENGTH]u8{ "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75", "f6c5600ed1dbdcfdf829081f5417dccbbd2b9288e0b427e65c8cf67e274b69009cd142475e15304f599f429f260a661b5df4de26746459a3cef7f32006e5d1c1", "d6f644b19812e97b5d871658d6d3400ecd4787faeb9b8990c1e7608288664be77257104a58d033bcf1a0e0945ff06468ebe53e2dff36e248424c7273117dac09", "1b86355f13a7f0b90c8b6053c0254399994dfbb3843e08d603e292ca13b8f672ed5e58791c10f3e36daec9699cc2fbdc88b4fe116efa7fce016938b787043818", "f368a29b71bd201a7ef78b5df88b1361fbe83f959756d33793837a5d7b2eaf660f2f6c7e2fbace01965683c4cfafded3ff28aab34e329aa79bc81e7703f68b86", "7a9b2a35095dcdfedfdf0ef810310b409e38c92c20cbd51088ea5e4bc4873bdacfeb29f14b7f2ed033d87fad00036da83d5c597a7e7429bc70cec378db4de6a6", "d1ff70451d1f0b94f551461c5ca239e498f571add4542c381e3eef84eac24aea6d12f8333ef4a05847e205ef4bb094921314364e7648176f567863d982042a85", "f74f2603939a53656948480ce71f1ce466685b6654fd22c61c1f2ce4e2c96d1cd02d162b560c4beaf1ae45f3471dc5cbc1ce040701c0b5c38457988aa00fe97f", "507294e03fdbc784dc3f575706c3ce53b3c4c37065e89ddd6b6de8bd2be655e15412e27695d32d2d6a3a0eaabe36ebddde78af0122a65ec41128c98c6fd30554", "4714870aff6c97ca09d135834fdb58a6389a50c11fef8ec4afef466fb60a23ac6b7a9c92658f14df4993d6b40a4e4d8424196afc347e97640d68de61e1cf14b0", "2d5be0f423fee59bf2149f996e72d9f5f8df90540a7d23b68c0d0d9a9a32d2c144891ca8fe4a3c713cb6eb2991578541dad291ba623dbd7107c6a891ba00bcc8", "a88ac22ca41e71e252c1f0d925de1ec174346e097c695e948d23016ab54cf21da6f0b0490ffa752bcc4893afc0c2caa64307705d1996f2959a3e03dc420c68cf", "b0b8828df9473f2763f9a48b0a9683451e98155436c2eff64c628fedbba0cca2360312271f3971f2969b1f828b1bb8251d3a43e12361824aca14f9a9affe2171", "831ce89c92608efda86cdf89d36e855bc73c5d17b2162c0013c14a2676ef4794dc53de6a54c1e3fb782acef5dd1192d36d0ab7fa88262cf0f6a16950e44a828c", "0b6f7fb0679a1ef009d5c8c70551d3b7013a5881b41ec2d597c3cf22e6aa13a1cf9a925b7a012feb67956c83b91cc32bef1de4cdbc6b2ff0cffbba319b54d15e", "987d0fc93db6a73fdb16493690fb42455c7c6fbafe9a276965424b12afad3512fb808d902faa8a019d639dc5ad07c235805e08f396147cf435913cfed501f65a", "06ef0364617146f6200c2cbc4280202226d701c2961940f57e7b60677587c66087f23bbcffa0de8692221f9434ac9a21e6df6428377cd145e1a456e2359d2cf6", "10dbd292472d3ff7279f3dac7fdb83c296bd61cbe80b0e26fbc14f871fd9771180d83879e812ec9841ba15a110e84a589c0eedfc14427c23ba56fa4fb7773de0", "1d383178e64d7071e749b2d560a22abc97e6514c31e800b5cc12c6f72ad43a9a0c4ce7db246219f3dea09afae6044a484de203148cb55f1057ee37b9420073bb", "d87a10a0bee363dcdf764831e807df5ee5500483c09056b38f854606f9e665566264b15af9fee8f9b84f3a7b6ddb67b92996ef790d10e899ba0758d5ab650caf", "1f60925cd5271a8ec9eb49ea4bf187f6a7dbc22eeb0e2dbc89d8381d0e73dea5bff5375a6db7e49fc427cb4fdf9f7ece577037adf91decfc38f303b1cb79ad44", "0ff3b2ffbda4cf938263e9449735618103a4d6a0cdeeda57367f6377d23849c3dce6851377f8f1b3d2ce3ff1dd6de0d64920d7790994782b4a8e2697e31f1900", "c6020ac00b701699227ccc9355156da0ad1d521ada5949cc89dd00661725be08fea4a2519ceb1e50acdd16e7127783f7ed5bfabe5238ce0da7ad2b4174c5509a", "e37ff6da226042c6fdd066c20f00e0d09c4f4dea104d8ea1fc513496ef24a0e17cd4bfb2e95781329a45d3885ca0e20f88e453dc9a4c4dc2acd0be756e3356b8", "4d272d73d4000f885ad1be048b7c7f92c2a8e5a01f30a96ed82849223606ad639f73155c85a128fbd2c26d3de30fb207e57b9f7ff21bfc79e0d7f0e2fb5189dc", "90cce547b76967676972c60e83944ffdc143078b6b40c722a0f2ac90d78eed0057843213076a9a7df528d0c0ebf3c00a91ae1c37f8850173fa2c03c41b6168ea", "4cea8c7ef657f9177c286081f8f016adae91a131a496e939ac86060e691afba57accc08ddbc423eb9d0817725faad9554c60f314929f30e881871e8782228918", "24077df741cb7ba88537d62c55fbff3ea81b603c31e6fd0d2e5d28e1a505f6192d5b2c1f98011152fef2c75901f66d489c045a4a3f98705c2b244c004f1579d4", "2af97e464526c024ef466db4616559919b769b350b7f6830ecfa5ffdeacd6eb570daf0ed25c0c56b194119f15247f63f5b94b54e01283b4b7a832586acac9e09", "abd9c33f8c791b27dd614e80ad77f1ff33c2621663b4dcbe5a88417a8b95b8d6788a9320678b589aa5b405897b2113523df1defa304953ea2ae1a229f2736450", "ad9e7ae1f68786c33ca713d4632b29ebcc9c9c040fc176ead8acb395a14c08324e824f7531f6a50ba0d4a17de958a08e54c9597dcc30781e22c0d953d06f9f4d", "020089a47cb0761c222c323aec2bdecdaa7a0d0ec094cda8c5755ba26844453c25b37e4bc98aab8adc55c9da75bcd83af62905d62e9044a5d64cd93d93b54b34", "d578a2d3fab982fbc7f1fa20630713c5a2a2cd9654a53822978d3efd2becc2a02e1fa1391dd11e139d1489aba688367ea9286e2a9ba8ef67009c80df81998614", "c1de14e1a09b03c688bd568ff4b4fa086baed2181d0d99a219fb937484ba67f093efe36966b0ea5209dadb6ef4f67c2d1f753d49c083a6241d2ab4557509404e", "cbb50e7e8a14cb9df08642609b6d737302d78cdcff74e1f53e895ae4a7cb093a571364dbbc2797962f54366ef65ead1c41a44ffe2ab0d56b7ae01e99a7a4e6fb", "85a564722dbefd268ed2e2e70fb377306c207a9c7edb634adcd79b8829aaad700c3a26cce44eba99aff46c4349f5e5056a87fcd2b63dd08b8b7b1f2f3ea06d6b", "ae77859a42c40e3973aa42bc8fbe8713444f65173580507d7c4bcc7c85d7f8c93204f433d506e912504ea37c766af17e649bdf6c8356f6e8e65bf4e9321987cb", "5b7c791e8018b14752ca7b91386d3ddbd3f9307a69ca71d977e274171aa5cae0b1a03960e842ca05fc0b95205a243fc8b28c36e4dd60ff000a47fb63547e6a0c", "f140bd9a11c309eb9da6ae1c8360cf2bc952a41a9ff228c066c0811df508313f59f1b6e6ffc6d14ef967f477c69463974aefd78d1c1dec9d8d35ff0c81dc29e8", "e411795f8b2a38c99a7b86c888f84c9b26d0f47f2c086d71a2c9282caf6a898820e2c1f3dc1fa45b20178da40f6cb7e4479d3d7155845ed7a4b8698b398f3d0c", "9178f65d74628c56ce3ace5b9ae7ecb84fc8a840ae33367a9c5534e6556301dc4fea4927d82289483496c39b929afb4a4ea92ded82c02057a7b8029828d8fb8d", "e11e1d056266f561bf3a9dede38228700e59971b3be992fea66a687887441976d8b29193707211dfb94dd1f7918473c3e99ff48a7c91068a1aaf7054febb9e2d", "acbaf243155ab6ca5f44c13061757fa060acbc5cf43d996b4f47209c22bf70c29af8dbc5c0a68ca45e42142db1540d2db70f6f27a917a3019dc92dadd0f639d6", "647b6deadb5aeb56e4087414fe2a76d6f57083dd6303a19e152445d108dc2bcd17926981d500b19b913b36a3b343b2e6781c805c1897664a218a2cfecc6a5238", "3ca97cdefcc384485ec2b6bebffe63d98f5675132a8b43d1f38bad4ff1982264fc4876ec637e918f855d855945b9b84eb82386bc6fc1e92695ec623001f8ddd1", "7b549433b4ef39abb90dcd3eb90c63562b7f3daa056670b2f712ebb7e9e78adfe7423e4b39810c1109fb640e84d32047468b155fe342d13e7f4d7ee019fa5922", "ec1d753e2280b8136b686ec81b03b3f8a7f98152868e3a68f0a2c456082c2faaa93c39ad573a6d21f4a3350df602249dc89ad28620d27ecc1d9e1f258badcd04", "bd582a787a21036df7049d501879977625601527d7ddd6f707463cb8b3839fbedbe233b8e69f1696d0e82b168d3491a3dbb6005b6224c198601dafbd50e14365", "4b4ff3bc763a976c16afdd8082efc7a5c98d60342f0ed5a654f567dacbc6414833e60ed1d6770bd42638fdae605c69be0219532125a186609f0825376ab59e45", "bdba173e58132092b0aa67ea5080f247e5b3710630a789c519b311f3848588f0bac8db3091ff8fd16875601636bef625e43b3d82cb51eb6693cdd1b2a5c872b8", "78a0eb5d7c0b05284056e1f19cbb42a99470bc81de4f9bc48708d28c5a877626e69167c58d4e840a7aa699bc6dddd972564d84ea502b41d83878e98e68f83c81", "a45021322d3f30747b3ceb7c1b1975ac4698984be76915f82cdeefe769f115d9dc5c70549e897b0ab8d5d61fc9e73ad1f7f49db39bb4e1298ac833d290eb1d04", "0b08accaae7044e54074fdcb7404a10c0703144d4499a644d9cfc60f973dc27dcdc65ac31750f7407ba96d025fb699e64ddcd1acd0dabafeeafccb5733225d3b", "07a2200290a2b7423a94f71892554b17196e2301e2e446ce09f65abcb45523268274128038925489671af9b899747b80e35a0a1b8613ecfb44e6be3152a2fd93", "b0220c772cbf6c1822e2cb38a437d0e1d58772417a4bbb21c961364f8b6143e05aa6316dca8d1d7b19e16448419076395f6086cb55101fbd6d5497b148e1745f", "962b64aae357d2a4fee3ded8b539bdc9d325081822b0bfc55583133aab44f18bafe11d72a7ae16c79ce2ba620ae2242d5144809161945f1367f41b3972e26e04", "d3115798e872fc1ca6b276368e8ea0926daec6ab1f8f08297e4348ff5f5fe4c6e5205413271babafd4929b070754bc5800e5db44790666ec4e2f6ac52a17e163", "2282084c042e92d7ba1a9e1ee5527762e91c4ffee7a8676c4a4a0facefad352bed2d3c322368cfe813186084c5386e9f22f803dfe0a1b424cab3e0a95a6dc3f9", "fd4eaf2071e8d9cf36688c3be714f5e363a5b4932f509914c613d1b8987d188e82cdd12b6ab07ea2f676fad1789275ef37253260a817a61079bc0ea567ee094a", "5ac08e89d884de3f086c60e8f36e754cf0ae9be2f018a87b7f71b15c81356410077eaa075010eb48959783ba490dc7c9fec53573848d8929bd5fc0574552f58f", "0202004b03bf7be513c96ef3fa6e48fce6e02f858d3bd95edba5adbdce60b2d7a4aa8700de15fc421b5e6847d8fb8be1bd24acd16314cfd94f0fa69ff6d637b4", "9814d48ae1bfd731b32f0a829f20507ec9bd6b77609053718f7e2053b53c7a264bbab6a96d3d54a7f9a736570d11b1f99afb1735149f43cfee9b6f87886d3ff6", "c1b0f5c6d3b03dfe4a2602e67242f54e344090b66e01100a469b129f583f016c7e27dddeaa438393dcc7ec54b0b57c9ba7af007f9b56db5f6fb677d972a31362", "01d35c10c6c38c2dcf48f7eebb3235fb5ad74a65ec4cd016e2354c637a8fb49b695ef3c1d6f7ae4cd74d78cc9c9bcac9d4f23a73019998a7f73038a5c9b2dbde", "b83086cd8494e55708ad7ecd82dfb4bca1bda61ecbb7caf0c68967902e709345e5d8305eb7ac0d588afc6cbb75161aa9c8c7e0ea986bd833dafe5e1ccd37345a", "f2f1cb2b1da21f7df43034baf8ec6bc992a46a022a40f81339240fdae572dbdf34fcf26e97cabc0e001c0aa65607b45585d107c48d676d6e2f389fd801d1fed7", "1b049c5022acb0a6f886cb607629db83dee7ee8f623f8f0fcf352b8f5052036cc7e992e9f79bc424173abb07df8ccfb058f13cfe2a14925a1bb67f4447dd8929", "6c450032dd6b928bdb327b9892d15808163d314aeff37089380ca01ee4b1c8db739f71de29446c385fc8e0f12482ccb04ca1572e243affc7d77ed7bbc083be0d", "73fa82cfc129fb937094b53346e04ff29e44c67250f6952b63ef561bc7cc1169fd94368a252ae408f496c17684145d65cd46ec9c5a03eb59ecc35f6a1d2fc159", "d7ef283e6194befc2498bbced7f58bdf60cfcf10011fc5817b69cb13d63725017aa1e632ea3c609f6a5eb8a057ddb82953538f3e2a738262a11ddcd47f13752d", "216d4ffba1e94e8f281b06feb558346eeb0ae567c0a1d0c56ba2df704f45b2a6e6d91f97c5c00ebbcdfeb14b438bd9e56f2eb36ca64d22392520f3496f28fef5", "7e076f0892677d21072e99258203151146d4bc78ad6ed68edc939ba080c473ab66b10d38834e33abde71830dbd8529d895c7ea5f5773f1457d7c71bc3824b7c8", "1a3d403b46c595edfb71d10b4cb9e1b9ce4e44e28db6ba2a0334195816b85e6eba147bc6160864a0fe28166f99148476893a031a38a814e7136497296865f3c9", "4c4c8dcd6ba88f47a51df4dabdf227c335d70d5f4941b76e698536693e53c50241ef0264ea6f6dc5527485ddbe7a76900405158e32fef5ed184919943148da67", "8ea2d14c839946461666ab0a5966a10886e29d0a890104b123bb94d0af9011d8a961681fb95df98d00d5d351985f61f2e2eba2d91fd8032566b856d8408a09b0", "c642ba36e76cc1660c342d163fb32e4be8482072e641dd6b3662c447ecbc24f1b5e16ad4b83eed093c6f5999f1b2a0086fc23526cef9241a5a052c720bb5afde", "b9451e8c39c4276c2192939d49cbcb2b85a048e4f38bb5d3282e24c417de893ac2ff0acdef20036ed4deddbb526f992cd56f992aaba93d4edd3a628a4e53c811", "9a8c06cf6123391e9ee4d2441b7e534fc9551c242fb2b96fad45a7210edc010c36704b9ca1a07e935e6ff1413768e2f27726b213b16961633341ea82d75c5df3", "54b998867e8ac0d3eebcbf2252c107ad6dc5b557db5b7cb65a147475db99831011878784a62678a6fada687705ef68d048047f05b51db9c09168c4a7ad877036", "cb8d0d18db405d9d964ab61d1a5c00024df3805a329bf1500bec74d3ec1f1d0574da0b86153c9d8e317603bdb09e46d54d44551992a2464f0335a8398a2f2aee", "2fe6df89dcac80c7a03c2bc39633c12ae2898019117aacf77e490fa54cb8deb34a0d29ce778ee4f674831921853a15b541773486d5ac785163744e6d24ba388d", "c3e410354f6f890d0f3027805da471340f91db2a858501059124d3175eb7d637ca3637f7f95bafde0d74d026be7bf086e48931e299d68edc43e0a7ac4eac75c4", "107068fb436d658c0a96157316af41d323e582ea9c81146933ead563bf2c2a05b2c77ceeef57c01cd09ec28f6507238e930b1b7241d731f83194440f9256e5a6", "62b5337f5be290d028dc41dde08682ed7b0a7a842eae36dc6f7220e220012aeca98b2dac28325d1f78beef84352689c07c3a45f549e98ba908b010abceca9978", "6b6f3ac1316d9e8d1505ad163b70077df1df92568139721b32c23e5d84dc2fd742a4bad56bf0efacb3f3e63bbfb08a829b16df8cc1799eb199cd5d56be2b9d52", "bf8ed43d3aeebeb9b00d91013fbbb463b2f4b13e7ffc42741aeb9f0190a91b0401bb4fac68cc009d314287876c54d2f18891e6eee86fbe7125171559be6a03d7", "056ffe9a8b3a346abb92cf36efb74417748a044c4ca07f94e7bb076eeafa67073a85fcc1b17e7953138f304bbea7d0592e910e55b489e22c9015dc4e04ba76dc", "a945652aabf28d5ed6bb284a35fd4296a9a0ddebc81bf59991759ecaa7fb95a59628cf1ae75c88177fa3993e0cd0f138a807cdc01d17ca3922817ad1dc1c39e7", "bb4ec00ac4a82ed71af3936559c5940582218da063554c6f3efbb6d67cc808a2d6dbf088d0f371a4a1259efb1f1edeefa8093cab25551519d7ac6142711e50fe", "3a60fa8bede0f822c5dea75eff151ed5841d11b301c474a13571aff2dd0e216b4bc072b9ce409a70c6e6ff35bcae2f0950880d943f95775dd8f54d94b12d47c3", "bed8ac47aef0271fe40227247ddcdfd6b4885effeba3042f34b6fd525ab56cbdf72050cb71b1d42ae0ee1c548b36668b9297279d661380dffa39e66aa2959f99", "dfecce5852f67e858304fc5dc0c15cb29e28c69af4e2c117d333ea46d2ef2b0379a983507bc16e827b86c2433404159b759de91eb9ae975f338bacf38ad20371", "51585d172675d427009ea1658ac2a4d67a600e65034cb7f8eb34a39add704b67ae0a2798b7d7e7a16ee0f6902a165a0646cd9fe1cc777a07c6bfa14028c8eec8", "9e4246d4d3725a67a909dd1a4f06c627627942c0bb31eb4c614cab842e6bfb9faa7e8938575a2402832ac353a6fb47f4918b31d754eb9764e714f6925462b54e", "89e0446c3ff5a04b6d707ef43a77e2b349791f402930dbdb74bbab73d5215e294146ba7bd2fa269aee38564ef11a9ccaf5278f9e82687126dcf20d481d470617", "39ba3c74b23cb7deffb5d59624e320c08692637057daaaeea4d847e1d3b6a2ce6895ff3c609d57da490484b030ed231d5bdfafcfe264bd3d91cddb39c2d036ab", "db3a1fb5909f50e02e1626616247de6867e9e332d0eeef4650367cf0058f4764eb4a3869d3931b5ef6fc7a044a868b5fa894462df15c3954e88cd70c9a1de1b2", "86497b815f64702e2ac6aca1f1d16f7159b4f0b34f6e92a41e632982a7291465957e0ef171042b9630bb66c6e35051613f99bdc95c371eeb46bff8c897eba6e9", "21883a9b2ffa353c93fea49ea8b92be22797e6e8b360ebac8ed894b702766458a825adf67d9561d6758f5f9cc3aec7a4b2e4464a08e6959029dbc0b2f3fc6105", "70ff99fd241905992cc3fff2f6e3f562c8719d689bfe0e53cbc75e53286d82d8767aed0959b8c63aadf55b5730babee75ea082e88414700d7507b988c44c47bc", "2327e3b2946432dd2f4bce390ca652ec5e90f44fced0e921f612cf6d594cfc5e21b56e30a30dc0157e2c37a59cd37951f20cb9e2bc2d815a2676c01c2f827d51", "ec90d76ee1a1643126f53609a2721ad4a130c57d4dd0416a5d1b0bc43419ed6b3b0e82e0ff5eb76e94accfacb8bf72d7c92b622a0842d9a5b8b6e40fa2fc5231", "48e257ba5ef0c4b0b9769d26d5990d87f058430e368802c1f9a47195a6fa23ede9bbadc4c46ef2a8480cbfa0ced25dad522ca1752a66d5b43a72486f82c7b934", "e4f39bcd76fe94bfa84b31b0b9f3d2fe065b1e01ff2c3c0cd6f26b942f3c73a35031b9ecb4d82418a52892dabb459b27f0ba04af5e90636edf0b2caaa2d7906a", "3b6dd73c9552f2381107bf206b49c7967fdc5f5011d877d9c576bb4da6d74fbbabf46a1105242d7c645978e54c0b44adaf06d9f7aa4703e8a58829f6d87c5168", "470edb01e9dc9db187acdc9fa594e35b40831f9ddf76309d4a99a7aef1f0d9f79b5a4c9a22a38aeca3a1c2d6ceaeb603899577a30643a97872717c025a9a4fdc", "8cfcdd655481cca50730fe51ee985e9b51946f1345cb6a1801e5e0ed64ef979f431d5a7c3bd2a479d6d82e354210741956d194ee0febbc132b35907f4e2be32f", "a53d93726f1ba688a57267326473eceddc4ccf992d5c53429ca3edd4b122b4fe0b0568887d65c220cbac93fc4f612f97a09eb95e9f903409c78a22eee4fa1781", "0cda6b04d9466bb7f3995c16732e1347f29c23a64fe0b085fadba0995644cc5aa71587423c274c10e09518310c5f866cfaceb229fabb574219f12182eb114182", "c825949632e509824543f7eaf159fb6041722fce3c1cdcbb613b3d37ff107c519417baac32f8e74fe29d7f4823bf6886956603dca5354a6ed6e4a542e06b7d28", "fa9121c7b32b9e01733d034cfc78cbf67f926c7ed83e82200ef86818196921760b4beff48404df811b953828274461673c68d04e297b0eb7b2b4d60fc6b566a2", "c01d080efd492776a1c43bd23dd99d0a2e626d481e16782e75d54c2503b5dc32bd05f0f1ba33e568b88fd2d970929b719ecbb152f58f130a407c8830604b70ca", "55ddd8ac210a6e18ba1ee055af84c966e0dbff091c43580ae1be703bdb85da31acf6948cf5bd90c55a20e5450f22fb89bd8d0085e39f85a86cc46abbca75e24d", "5e9eb0e4b270d086e77eeaf3ce8b1cfc615031b8c463dc34f5c139786f274f22accb4d89e8f40d1a0c2acc84c4dc0f2bab390a9d9495493bd617ed004271bb64", "eaa30f93760743ac7d0a6cb8ed5ef3b30c59097bc44d0ec337344301deba9fb92b20c488d55de415f6aaed0df4925b42894b81d2e1cde89d91ec7f6cc67262b4", "a8bff469314a1ce0c990bb3fd539d92accb6249cc674b559bc9d3898b7a126fee597197fa42c971443470053c7d7f54b09371a59b0f7af87b1917c5347e8f8e0", "c0c27aea8dbe169c4cf25176cbf12db708fd6303db8cf94a1cfb402c1680d3d68f39bc5b9a10970dd5373cb0fe1cb36fa50e33165140d72933ba87af9d5d1ffe", "d6f856c92a5a694dec299f5a4765bed80e4e7431aa5505f82b21584dd1f1fe970f698bec5a3f4faa593d1aac944a96c21b85463a773cdf3ad87c4a00fb9e5073", "130396a75cb483f2eee8c56d8a668bb3d2641f5243212c0bee2bd33da096ad9eb8179fe18f9eaacf76e09fae9de4c3f14ba13341e345be05bf76c182cc3468cb", "f241de612b01aa2fa3cf01531d2a8e5e17fc761dfd48a704a834a47f57d6eade7804ecc39be42fdef16ec6adeaf7c01c2fd0c4cc97d3860907cfa4a3b36d0c05", "0ae7a79758a9ffbd1c04aa080bfa82daf9641f9c2a1cc82b628cbe4006bd47701c78e5022d2ca5ca5384d26d93fb16d595b9775dab17c88ef38e4ce9fdac4b52", "139de16e90ad012e39f72279140f4f6b12bb93f1cbcffbd1b132f39e7f92822d2b56beafc9ed83a0bf59c5525ffd125b83294b65f51f6e8ebbf85eb1aba85b87", "ccd869ee70892a0f5f3c269b9e21ffc99703855c1c652774febbaf1311bd58c80fb66bc3f747dd98b2f11ad9f5d8311b7ca706d456fc82ccd46bfb01f19e8d87", "77469b56910b022f45f509dcfca04494d8e7978073debf96398cb5a86f31bbe55f2a807a3271b8fe124171416917ab01a87acc7bf005977caaf7b484d87d6a93", "577a80f7cb393ac140af066b524166bb02a8059980b65fd100ecdcbec7721d2d0519a151ae730d4b6d9b97a8e5d2415aa8157856aeae4a7444171ef2a9db252b", "9986e67bf52a755f8924f28dae9627f889a45d466ce8616c4ed68ec3afd7a3a14785c335c6c68d62e7379af762b2bc17117a902083a99fae337a268a5d4f4427", "828613968b501dc00a97e08c73b118aa8876c26b8aac93df128502ab360f91bab50a51e088769a5c1eff4782ace147dce3642554199876374291f5d921629502" };

    var digest_buffer: [SHA_512_DIGEST_LENGTH]u8 = undefined;
    for (0..64) |i| {
        var ctx = sha512_new();
        for (0..i) |_|
            try sha512_update(&ctx, "a");
        sha512_final(&ctx, &digest_buffer);

        const ref = sha.hex_to_bytes(SHA_512_DIGEST_LENGTH, reference[i]);
        try testing.expectEqualSlices(u8, ref[0..], digest_buffer[0..]);
    }
}

test "SHA-512 maximum length violation (simulated)" {
    var ctx = sha512_new();
    ctx.message_length = (1 << 125) - 1; // 2^128 - 8 bits
    try testing.expectError(sha.MessageLengthLimitExceeded, sha512_update(&ctx, "a"));
}

// Reference hashes computed with PyCryptodome.
test "SHA-512/224 basic test" {
    try sha.run_hash_precomputed_tests(
        Sha512Ctx,
        SHA_512_224_DIGEST_LENGTH,
        sha512_224_new,
        sha512_224_update,
        sha512_224_final,
        &.{
            .{ .message = "", .hash = "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4" },
            .{ .message = "abc", .hash = "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa" },
            .{
                .message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                .hash = "e5302d6d54bb242275d1e7622d68df6eb02dedd13f564c13dbda2174",
            },
            .{
                .message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                .hash = "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9",
            },
        },
    );
}

// https://www.di-mgt.com.au/sha_testvectors.html
test "SHA-512/256 basic test" {
    try sha.run_hash_precomputed_tests(
        Sha512Ctx,
        SHA_512_256_DIGEST_LENGTH,
        sha512_256_new,
        sha512_256_update,
        sha512_256_final,
        &.{
            .{ .message = "", .hash = "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a" },
            .{ .message = "abc", .hash = "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23" },
            .{
                .message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                .hash = "bde8e1f9f19bb9fd3406c90ec6bc47bd36d8ada9f11880dbc8a22a7078b6a461",
            },
            .{
                .message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                .hash = "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a",
            },
        },
    );
}

// https://www.di-mgt.com.au/sha_testvectors.html
test "SHA-384 basic test" {
    try sha.run_hash_precomputed_tests(
        Sha512Ctx,
        SHA_384_DIGEST_LENGTH,
        sha384_new,
        sha384_update,
        sha384_final,
        &.{
            .{ .message = "", .hash = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" },
            .{ .message = "abc", .hash = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7" },
            .{
                .message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                .hash = "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b",
            },
            .{
                .message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                .hash = "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
            },
        },
    );
}
