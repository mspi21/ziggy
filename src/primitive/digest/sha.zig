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
    const MESSAGE_SCHEDULE_WORDS = 80;

    message_schedule: [MESSAGE_SCHEDULE_WORDS]u32,
    hash: [SHA_1_DIGEST_LENGTH / 4]u32,
    message_buffer: [BLOCK_SIZE]u8,
    message_length: u64,
};

const Sha2Ctx = struct {
    const BLOCK_SIZE = 512 / 8;

    message_schedule: [16]u32,
    hash: [8]u32,
    message_buffer: [BLOCK_SIZE]u8,
    message_length: u64,

    t_is_224: bool,
};

const Sha3Ctx = struct {
    const BLOCK_SIZE = 1024 / 8;

    message_schedule: [16]u64,
    hash: [8]u64,
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
        .message_buffer = undefined,
        .message_length = 0,
    };
    @memcpy(&ctx.hash, &SHA_1_IV);
    return ctx;
}

pub fn sha1_update(ctx: *Sha1Ctx, message: []const u8) !void {
    // SHA-1 can digest a message of a maximum length of (2^64 - 1) bits due to the nature of its padding.
    if (ctx.message_length + message.len > ((1 << 64) / 8))
        return MessageLengthLimitExceeded;

    const cnt_buffered_bytes = ctx.message_length % Sha1Ctx.BLOCK_SIZE;

    // Simplest case - the message did not fully fill the block size
    // so it's just copied to the context and no hashing is done yet.
    if (cnt_buffered_bytes + message.len < Sha1Ctx.BLOCK_SIZE) {
        @memcpy(
            ctx.message_buffer[cnt_buffered_bytes .. cnt_buffered_bytes + message.len],
            message[0..],
        );
        ctx.message_length += message.len;
        return;
    }

    // Otherwise: first, copy & hash the first block.
    @memcpy(
        ctx.message_buffer[cnt_buffered_bytes..],
        message[0 .. Sha1Ctx.BLOCK_SIZE - cnt_buffered_bytes],
    );
    sha1_hash_one_block(ctx);
    var cnt_message_bytes_processed = Sha1Ctx.BLOCK_SIZE - cnt_buffered_bytes;
    ctx.message_length += cnt_message_bytes_processed;

    // Then, as long as there is at least another block available, copy and hash it.
    while (message.len - cnt_message_bytes_processed >= Sha1Ctx.BLOCK_SIZE) {
        @memcpy(ctx.message_buffer[0..], message[cnt_message_bytes_processed .. cnt_message_bytes_processed + Sha1Ctx.BLOCK_SIZE]);
        sha1_hash_one_block(ctx);
        ctx.message_length += Sha1Ctx.BLOCK_SIZE;
        cnt_message_bytes_processed += Sha1Ctx.BLOCK_SIZE;
    }

    // Finally, copy any leftover bytes to the context buffer without hashing.
    const cnt_leftover_bytes = message.len - cnt_message_bytes_processed;
    @memcpy(
        ctx.message_buffer[0..cnt_leftover_bytes],
        message[cnt_message_bytes_processed..],
    );
    ctx.message_length += cnt_leftover_bytes;
}

pub fn sha1_final(ctx: *Sha1Ctx, out: *[SHA_1_DIGEST_LENGTH]u8) void {
    // The message length is stored in the padding as a 64-bit int.
    const message_length_bytes = 64 / 8;

    const cnt_leftover_bytes = ctx.message_length % Sha1Ctx.BLOCK_SIZE;

    // Simpler case: The leftover message is shorter than 446 bits
    // (or 55 bytes) and the padding only spans one block.
    if (cnt_leftover_bytes < Sha1Ctx.BLOCK_SIZE - (message_length_bytes)) {
        const cnt_padding_bytes = Sha1Ctx.BLOCK_SIZE - message_length_bytes - cnt_leftover_bytes;

        // The padding (without the message length) is a single 1 bit followed by 0 bits.
        ctx.message_buffer[cnt_leftover_bytes] = 0x80;
        @memset(ctx.message_buffer[cnt_leftover_bytes + 1 .. cnt_leftover_bytes + cnt_padding_bytes], 0x00);

        // The length is appended.
        const length = serialize_int_big_endian(u64, ctx.message_length * 8);
        @memcpy(ctx.message_buffer[cnt_leftover_bytes + cnt_padding_bytes ..], length[0..]);

        // The padded block is finally hashed.
        sha1_hash_one_block(ctx);
    }
    // Otherwise, the padding spans 2 blocks in total
    // and two more hash iterations are performed.
    else {
        // Pad and hash the first block.
        ctx.message_buffer[cnt_leftover_bytes] = 0x80;
        @memset(ctx.message_buffer[cnt_leftover_bytes + 1 ..], 0x00);
        sha1_hash_one_block(ctx);

        // Hash the second block.
        @memset(ctx.message_buffer[0..(Sha1Ctx.BLOCK_SIZE - message_length_bytes)], 0x00);
        const length = serialize_int_big_endian(u64, ctx.message_length * 8);
        @memcpy(ctx.message_buffer[(Sha1Ctx.BLOCK_SIZE - message_length_bytes)..], length[0..]);
        sha1_hash_one_block(ctx);
    }

    // Serialize the result.
    for (0..SHA_1_DIGEST_LENGTH / 4) |w| {
        const serialized_word = serialize_int_big_endian(u32, ctx.hash[w]);
        @memcpy(out[(w * 4)..(w * 4 + 4)], serialized_word[0..]);
    }
}

pub fn sha1_hash_one_block(ctx: *Sha1Ctx) void {
    // Prepare the message schedule.
    for (0..Sha1Ctx.BLOCK_SIZE / 4) |t|
        ctx.message_schedule[t] = deserialize_int_big_endian(u32, @ptrCast(ctx.message_buffer[(t * 4)..(t * 4 + 4)]));
    for (Sha1Ctx.BLOCK_SIZE / 4..Sha1Ctx.MESSAGE_SCHEDULE_WORDS) |t| {
        ctx.message_schedule[t] = rotl(
            u32,
            ctx.message_schedule[t - 3] ^ ctx.message_schedule[t - 8] ^ ctx.message_schedule[t - 14] ^ ctx.message_schedule[t - 16],
            1,
        );
    }

    // Initialize working variables.
    var a = ctx.hash[0];
    var b = ctx.hash[1];
    var c = ctx.hash[2];
    var d = ctx.hash[3];
    var e = ctx.hash[4];

    // Perform the actual hashing.
    inline for (0..Sha1Ctx.MESSAGE_SCHEDULE_WORDS) |t| {
        const tmp = rotl(u32, a, 5) +% sha1_f(t, b, c, d) +% e +% sha1_k(t) +% ctx.message_schedule[t];
        e = d;
        d = c;
        c = rotl(u32, b, 30);
        b = a;
        a = tmp;
    }

    // Add the result to the previous hash state.
    ctx.hash[0] +%= a;
    ctx.hash[1] +%= b;
    ctx.hash[2] +%= c;
    ctx.hash[3] +%= d;
    ctx.hash[4] +%= e;
}

inline fn sha1_f(t: comptime_int, x: u32, y: u32, z: u32) u32 {
    return switch (t) {
        0...19 => ch(u32, x, y, z),
        20...39 => parity(u32, x, y, z),
        40...59 => maj(u32, x, y, z),
        60...79 => parity(u32, x, y, z),
        else => @compileError("SHA-1 `f` function called with invalid value of `t`."),
    };
}

inline fn sha1_k(t: comptime_int) u32 {
    return switch (t) {
        0...19 => 0x5a827999,
        20...39 => 0x6ed9eba1,
        40...59 => 0x8f1bbcdc,
        60...79 => 0xca62c1d6,
        else => @compileError("SHA-1 `k` constant requested with invalid value of `t`."),
    };
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

// ----------------------------------- Non-linear functions ----------------------------------- //

fn ch(T: type, x: T, y: T, z: T) T {
    return (x & y) ^ (~x & z);
}

fn parity(T: type, x: T, y: T, z: T) T {
    return x ^ y ^ z;
}

fn maj(T: type, x: T, y: T, z: T) T {
    return (x & y) ^ (x & z) ^ (y & z);
}

// ----------------------------------- HELPERS ----------------------------------- //

fn rotl(T: type, word: T, bits: comptime_int) T {
    if (comptime bits >= @bitSizeOf(T))
        @compileError("Will not rotate word left by more bits than it has!");
    return (word << bits) | (word >> (@bitSizeOf(T) - bits));
}

fn serialize_int_big_endian(T: type, int: T) [@sizeOf(T)]u8 {
    var res: [@sizeOf(T)]u8 = undefined;
    for (0..@sizeOf(T)) |i|
        res[i] = @truncate(int >> @intCast(8 * (@sizeOf(T) - i - 1)));
    return res;
}

fn deserialize_int_big_endian(T: type, bytes: *const [@sizeOf(T)]u8) T {
    var res: T = 0;
    for (0..@sizeOf(T)) |i|
        res |= @as(T, bytes[i]) << @intCast(8 * (@sizeOf(T) - i - 1));
    return res;
}

// ----------------------------------- TEST VECTORS ----------------------------------- //

fn hex_nibble_to_int(ascii_hex: u8) u4 {
    const x = ascii_hex;
    return @intCast(if (x >= '0' and x <= '9')
        x - '0'
    else if (x >= 'a' and x <= 'f')
        10 + (x - 'a')
    else if (x >= 'A' and x <= 'F')
        10 + (x - 'A')
    else
        @panic("Argument is not a valid hex digit!"));
}

fn hex_to_bytes(L: comptime_int, hex_string: *const [2 * L]u8) [L]u8 {
    var res: [L]u8 = undefined;
    for (0..L) |i| {
        res[i] = @as(u8, hex_nibble_to_int(hex_string[2 * i])) << 4;
        res[i] |= hex_nibble_to_int(hex_string[2 * i + 1]);
    }
    return res;
}

// https://www.di-mgt.com.au/sha_testvectors.html
test "SHA-1 basic test" {
    const tests = [_]struct {
        message: []const u8,
        hash: *const [2 * SHA_1_DIGEST_LENGTH]u8,
    }{
        .{ .message = "", .hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
        .{ .message = "abc", .hash = "a9993e364706816aba3e25717850c26c9cd0d89d" },
        .{
            .message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            .hash = "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
        },
        .{
            .message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            .hash = "a49b2446a02c645bf419f995b67091253a04a259",
        },
    };

    var digest_buffer: [SHA_1_DIGEST_LENGTH]u8 = undefined;

    for (tests) |t| {
        var ctx = sha1_new();
        try sha1_update(&ctx, t.message);
        sha1_final(&ctx, &digest_buffer);

        const reference = hex_to_bytes(SHA_1_DIGEST_LENGTH, t.hash);
        try testing.expectEqualSlices(u8, reference[0..], digest_buffer[0..]);
    }
}

test "SHA-1 padding test" {
    // TODO
}
