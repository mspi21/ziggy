const std = @import("std");
const testing = std.testing;

const sha = @import("./sha_core.zig");
pub const MessageLengthLimitExceeded = sha.MessageLengthLimitExceeded;

pub const DIGEST_LENGTH = 160 / 8;
pub const MESSAGE_BITS_LIMIT = 1 << 64;

pub const Sha1Ctx = struct {
    pub const BLOCK_SIZE = 512 / 8;
    pub const MESSAGE_SCHEDULE_WORDS = 80;
    pub const WordType = u32;

    hash: [DIGEST_LENGTH / @sizeOf(WordType)]WordType,
    message_buffer: [BLOCK_SIZE]u8,
    message_length: u64,
};

const SHA_1_IV = [_]u32{ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };

pub fn sha1_new() Sha1Ctx {
    var ctx = Sha1Ctx{
        .hash = undefined,
        .message_buffer = undefined,
        .message_length = 0,
    };
    @memcpy(&ctx.hash, &SHA_1_IV);
    return ctx;
}

pub fn sha1_update(ctx: *Sha1Ctx, message: []const u8) !void {
    return sha.generic_update(
        Sha1Ctx,
        MESSAGE_BITS_LIMIT,
        &sha1_compress_block,
        ctx,
        message,
    );
}

pub fn sha1_final(ctx: *Sha1Ctx, out: *[DIGEST_LENGTH]u8) void {
    return sha.generic_final(
        Sha1Ctx,
        Sha1Ctx.WordType,
        u64,
        DIGEST_LENGTH,
        sha1_compress_block,
        ctx,
        out,
    );
}

pub fn sha1_compress_block(ctx: *Sha1Ctx) void {
    // Prepare the message schedule.
    var message_schedule: [Sha1Ctx.MESSAGE_SCHEDULE_WORDS]Sha1Ctx.WordType = undefined;

    for (0..Sha1Ctx.BLOCK_SIZE / @sizeOf(Sha1Ctx.WordType)) |t|
        message_schedule[t] = sha.deserialize_int_big_endian(u32, @ptrCast(ctx.message_buffer[(t * 4)..(t * 4 + 4)]));
    for (Sha1Ctx.BLOCK_SIZE / @sizeOf(Sha1Ctx.WordType)..Sha1Ctx.MESSAGE_SCHEDULE_WORDS) |t| {
        message_schedule[t] = sha.rotl(
            Sha1Ctx.WordType,
            message_schedule[t - 3] ^ message_schedule[t - 8] ^ message_schedule[t - 14] ^ message_schedule[t - 16],
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
        const tmp = sha.rotl(Sha1Ctx.WordType, a, 5) +% sha1_f(t, b, c, d) +% e +% sha1_k(t) +% message_schedule[t];
        e = d;
        d = c;
        c = sha.rotl(Sha1Ctx.WordType, b, 30);
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
        0...19 => sha.ch(u32, x, y, z),
        20...39 => sha.parity(u32, x, y, z),
        40...59 => sha.maj(u32, x, y, z),
        60...79 => sha.parity(u32, x, y, z),
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
