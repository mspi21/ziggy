const std = @import("std");
const testing = std.testing;

// ----------------------------------- ERROR DEFINITIONS -----------------------------------  //

const KeyStreamDepleted = error.KeyStreamDepleted;

// ----------------------------------- ChaCha20 CONSTANTS -----------------------------------  //

const SALSA20_BLOCK_SIZE = 512 / 8;
const SALSA20_BLOCK_WORDS = SALSA20_BLOCK_SIZE / 4;

const SALSA20_KEY_SIZE = 256 / 8;
const SALSA20_KEY_WORDS = SALSA20_KEY_SIZE / 4;
const SALSA20_128_KEY_SIZE = 128 / 8;
const SALSA20_128_KEY_WORDS = SALSA20_128_KEY_SIZE / 4;

const SALSA20_NONCE_SIZE = 64 / 8;
const SALSA20_NONCE_WORDS = SALSA20_NONCE_SIZE / 4;

const SALSA20_COUNTER_SIZE = 64 / 8;
const SALSA20_COUNTER_WORDS = SALSA20_COUNTER_SIZE / 4;

const SALSA20_CONSTANT_WORDS = 128 / 8 / 4;

const SALSA20_256_CONSTANTS = [SALSA20_CONSTANT_WORDS]u32{
    bytes_to_word_le("expa"),
    bytes_to_word_le("nd 3"),
    bytes_to_word_le("2-by"),
    bytes_to_word_le("te k"),
};
const SALSA20_128_CONSTANTS = [SALSA20_CONSTANT_WORDS]u32{
    bytes_to_word_le("expa"),
    bytes_to_word_le("nd 1"),
    bytes_to_word_le("6-by"),
    bytes_to_word_le("te k"),
};

// ----------------------------------- CONTEXT MANAGEMENT -----------------------------------  //

pub const Salsa20Ctx = struct {
    key: [SALSA20_KEY_WORDS]u32,
    nonce: [SALSA20_NONCE_WORDS]u32,
    counter: [SALSA20_COUNTER_WORDS]u32,
    constants: [SALSA20_CONSTANT_WORDS]u32,
    state: [SALSA20_BLOCK_WORDS]u32,
    working_state: [SALSA20_BLOCK_WORDS]u32,
    keystream_idx: u8,
};

pub fn salsa20_new(
    key: *const [SALSA20_KEY_SIZE]u8,
    nonce: *const [SALSA20_NONCE_SIZE]u8,
    counter: *const [SALSA20_COUNTER_SIZE]u8,
    constants: *const [SALSA20_CONSTANT_WORDS]u32,
) Salsa20Ctx {
    var ctx = Salsa20Ctx{
        .key = undefined,
        .nonce = undefined,
        .counter = undefined,
        .constants = undefined,
        .state = undefined,
        .working_state = undefined,
        .keystream_idx = undefined,
    };

    salsa20_deserialize(SALSA20_KEY_WORDS, key, &ctx.key);
    salsa20_deserialize(SALSA20_COUNTER_WORDS, counter, &ctx.counter);
    salsa20_deserialize(SALSA20_NONCE_WORDS, nonce, &ctx.nonce);
    @memcpy(&ctx.constants, constants);

    salsa20_block_function(&ctx);
    ctx.keystream_idx = 0;

    return ctx;
}

pub fn salsa20_destroy(ctx: *Salsa20Ctx) void {
    @memset(&ctx.key, 0);
    @memset(&ctx.nonce, 0);
    @memset(&ctx.state, 0);
    @memset(&ctx.working_state, 0);
    ctx.keystream_idx = 0;
}

// ----------------------------------- ENCRYPTION/DECRYPTION -----------------------------------  //

pub fn salsa20_encrypt_inplace(ctx: *Salsa20Ctx, plaintext: []u8) !void {
    for (0..plaintext.len) |i| {
        try salsa20_ensure_keystream_expanded(ctx);
        const keystream: [*]const u8 = @ptrCast(&ctx.state);

        plaintext[i] ^= keystream[ctx.keystream_idx];
        ctx.keystream_idx += 1;
    }
}

pub fn salsa20_decrypt_inplace(ctx: *Salsa20Ctx, ciphertext: []u8) !void {
    return salsa20_encrypt_inplace(ctx, ciphertext);
}

fn salsa20_ensure_keystream_expanded(ctx: *Salsa20Ctx) !void {
    if (ctx.keystream_idx == SALSA20_BLOCK_SIZE) {
        try salsa20_increment_counter(ctx);
        salsa20_block_function(ctx);
        ctx.keystream_idx = 0;
    }
}

fn salsa20_increment_counter(ctx: *Salsa20Ctx) !void {
    for (0..SALSA20_COUNTER_WORDS) |idx| {
        const ov = @addWithOverflow(ctx.counter[idx], 1);
        ctx.counter[idx] = ov[0];

        if (ov[1] == 0)
            return;
    }
    return KeyStreamDepleted;
}

// ----------------------------------- KEYSTREAM EXPANSION -----------------------------------  //

pub fn salsa20_quarter_round(state: *[SALSA20_BLOCK_WORDS]u32, ia: u8, ib: u8, ic: u8, id: u8) void {
    var a = state[ia];
    var b = state[ib];
    var c = state[ic];
    var d = state[id];

    b ^= rol(a +% d, 7);
    c ^= rol(b +% a, 9);
    d ^= rol(c +% b, 13);
    a ^= rol(d +% c, 18);

    state[ia] = a;
    state[ib] = b;
    state[ic] = c;
    state[id] = d;
}

pub fn salsa20_column_round(state: *[SALSA20_BLOCK_WORDS]u32) void {
    salsa20_quarter_round(state, 0, 4, 8, 12);
    salsa20_quarter_round(state, 5, 9, 13, 1);
    salsa20_quarter_round(state, 10, 14, 2, 6);
    salsa20_quarter_round(state, 15, 3, 7, 11);
}

pub fn salsa20_row_round(state: *[SALSA20_BLOCK_WORDS]u32) void {
    salsa20_quarter_round(state, 0, 1, 2, 3);
    salsa20_quarter_round(state, 5, 6, 7, 4);
    salsa20_quarter_round(state, 10, 11, 8, 9);
    salsa20_quarter_round(state, 15, 12, 13, 14);
}

pub fn salsa20_double_round(state: *[SALSA20_BLOCK_WORDS]u32) void {
    salsa20_column_round(state);
    salsa20_row_round(state);
}

pub fn salsa20_hash_function(ctx: *Salsa20Ctx) void {
    // Copy state to working_state.
    @memcpy(&ctx.working_state, &ctx.state);

    // Perform all 20 rounds (10 row and 10 column rounds).
    for (0..10) |_| {
        salsa20_double_round(&ctx.working_state);
    }

    // Add the working_state to the state.
    for (0..SALSA20_BLOCK_WORDS) |i| {
        ctx.state[i] +%= ctx.working_state[i];
    }
}

pub fn salsa20_block_function(ctx: *Salsa20Ctx) void {
    // Reset state.
    {
        ctx.state[0] = ctx.constants[0];
        ctx.state[5] = ctx.constants[1];
        ctx.state[10] = ctx.constants[2];
        ctx.state[15] = ctx.constants[3];

        ctx.state[1] = ctx.key[0];
        ctx.state[2] = ctx.key[1];
        ctx.state[3] = ctx.key[2];
        ctx.state[4] = ctx.key[3];
        ctx.state[11] = ctx.key[4];
        ctx.state[12] = ctx.key[5];
        ctx.state[13] = ctx.key[6];
        ctx.state[14] = ctx.key[7];

        ctx.state[6] = ctx.nonce[0];
        ctx.state[7] = ctx.nonce[1];
        ctx.state[8] = ctx.counter[0];
        ctx.state[9] = ctx.counter[1];
    }

    // Perform the hashing.
    salsa20_hash_function(ctx);
}

// ----------------------------------- LITTLE ENDIAN HELPERS -----------------------------------  //

fn salsa20_serialize(L: comptime_int, words: *const [L]u32, bytes: *[L * 4]u8) void {
    for (0..L) |i|
        std.mem.writeInt(u32, @ptrCast(bytes[(i * 4)..(i * 4 + 4)]), words[i], .little);
}

fn salsa20_deserialize(L: comptime_int, bytes: *const [L * 4]u8, words: *[L]u32) void {
    for (0..L) |i|
        words[i] = std.mem.readInt(u32, @ptrCast(bytes[(i * 4)..(i * 4 + 4)]), .little);
}

fn bytes_to_word_le(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .little);
}

fn word_to_bytes_le(word: u32) [4]u8 {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, word, .little);
    return bytes;
}

// ----------------------------------- GENERIC HELPERS -----------------------------------  //

fn rol(word: u32, bits: comptime_int) u32 {
    return word << bits | word >> (32 - bits);
}

// ----------------------------------- TEST VECTORS -----------------------------------  //

fn test_quarter_round_function(y0: u32, y1: u32, y2: u32, y3: u32, z0: u32, z1: u32, z2: u32, z3: u32) !void {
    var dummy_state: [SALSA20_BLOCK_WORDS]u32 = undefined;
    dummy_state[0] = y0;
    dummy_state[1] = y1;
    dummy_state[2] = y2;
    dummy_state[3] = y3;
    salsa20_quarter_round(&dummy_state, 0, 1, 2, 3);
    try testing.expectEqualSlices(u32, &.{ z0, z1, z2, z3 }, dummy_state[0..4]);
}

// https://cr.yp.to/snuffle/spec.pdf
test "Salsa20 quarterround function" {
    try test_quarter_round_function(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    try test_quarter_round_function(0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x08008145, 0x00000080, 0x00010200, 0x20500000);
    try test_quarter_round_function(0x00000000, 0x00000001, 0x00000000, 0x00000000, 0x88000100, 0x00000001, 0x00000200, 0x00402000);
    try test_quarter_round_function(0x00000000, 0x00000000, 0x00000001, 0x00000000, 0x80040000, 0x00000000, 0x00000001, 0x00002000);
    try test_quarter_round_function(0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00048044, 0x00000080, 0x00010000, 0x20100001);
    try test_quarter_round_function(0xe7e8c006, 0xc4f9417d, 0x6479b4b2, 0x68c67137, 0xe876d72b, 0x9361dfd5, 0xf1460244, 0x948541a3);
    try test_quarter_round_function(0xd3917c5b, 0x55f1c407, 0x52a58a7a, 0x8f887a3b, 0x3e2f308c, 0xd90a8f36, 0x6ab2a923, 0x2883524c);
}

// https://cr.yp.to/snuffle/spec.pdf
test "Salsa20 rowround function" {
    var y1 = [_]u32{
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
    };
    const z1 = [_]u32{
        0x08008145, 0x00000080, 0x00010200, 0x20500000,
        0x20100001, 0x00048044, 0x00000080, 0x00010000,
        0x00000001, 0x00002000, 0x80040000, 0x00000000,
        0x00000001, 0x00000200, 0x00402000, 0x88000100,
    };
    salsa20_row_round(&y1);
    try testing.expectEqualSlices(u32, z1[0..], y1[0..]);

    var y2 = [_]u32{
        0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
        0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
        0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
        0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a,
    };
    const z2 = [_]u32{
        0xa890d39d, 0x65d71596, 0xe9487daa, 0xc8ca6a86,
        0x949d2192, 0x764b7754, 0xe408d9b9, 0x7a41b4d1,
        0x3402e183, 0x3c3af432, 0x50669f96, 0xd89ef0a8,
        0x0040ede5, 0xb545fbce, 0xd257ed4f, 0x1818882d,
    };
    salsa20_row_round(&y2);
    try testing.expectEqualSlices(u32, z2[0..], y2[0..]);
}

// https://cr.yp.to/snuffle/spec.pdf
test "Salsa20 columnround function" {
    var x1 = [_]u32{
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
    };
    const y1 = [_]u32{
        0x10090288, 0x00000000, 0x00000000, 0x00000000,
        0x00000101, 0x00000000, 0x00000000, 0x00000000,
        0x00020401, 0x00000000, 0x00000000, 0x00000000,
        0x40a04001, 0x00000000, 0x00000000, 0x00000000,
    };
    salsa20_column_round(&x1);
    try testing.expectEqualSlices(u32, y1[0..], x1[0..]);

    var x2 = [_]u32{
        0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
        0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
        0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
        0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a,
    };
    const y2 = [_]u32{
        0x8c9d190a, 0xce8e4c90, 0x1ef8e9d3, 0x1326a71a,
        0x90a20123, 0xead3c4f3, 0x63a091a0, 0xf0708d69,
        0x789b010c, 0xd195a681, 0xeb7d5504, 0xa774135c,
        0x481c2027, 0x53a8e4b5, 0x4c1f89c5, 0x3f78c9c8,
    };
    salsa20_column_round(&x2);
    try testing.expectEqualSlices(u32, y2[0..], x2[0..]);
}

// https://cr.yp.to/snuffle/spec.pdf
test "Salsa20 doubleround function" {
    var x1 = [_]u32{
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
    };
    const z1 = [_]u32{
        0x8186a22d, 0x0040a284, 0x82479210, 0x06929051,
        0x08000090, 0x02402200, 0x00004000, 0x00800000,
        0x00010200, 0x20400000, 0x08008104, 0x00000000,
        0x20500000, 0xa0000040, 0x0008180a, 0x612a8020,
    };
    salsa20_double_round(&x1);
    try testing.expectEqualSlices(u32, z1[0..], x1[0..]);

    var x2 = [_]u32{
        0xde501066, 0x6f9eb8f7, 0xe4fbbd9b, 0x454e3f57,
        0xb75540d3, 0x43e93a4c, 0x3a6f2aa0, 0x726d6b36,
        0x9243f484, 0x9145d1e8, 0x4fa9d247, 0xdc8dee11,
        0x054bf545, 0x254dd653, 0xd9421b6d, 0x67b276c1,
    };
    const z2 = [_]u32{
        0xccaaf672, 0x23d960f7, 0x9153e63a, 0xcd9a60d0,
        0x50440492, 0xf07cad19, 0xae344aa0, 0xdf4cfdfc,
        0xca531c29, 0x8e7943db, 0xac1680cd, 0xd503ca00,
        0xa74b2ad6, 0xbc331c5c, 0x1dda24c7, 0xee928277,
    };
    salsa20_double_round(&x2);
    try testing.expectEqualSlices(u32, z2[0..], x2[0..]);
}

fn test_hash_function(count: comptime_int, input: *const [SALSA20_BLOCK_SIZE]u8, reference: *const [SALSA20_BLOCK_SIZE]u8) !void {
    var dummy_ctx = Salsa20Ctx{
        .key = undefined,
        .nonce = undefined,
        .counter = undefined,
        .constants = undefined,
        .state = undefined,
        .working_state = undefined,
        .keystream_idx = undefined,
    };

    salsa20_deserialize(SALSA20_BLOCK_WORDS, input, dummy_ctx.state[0..]);
    for (0..count) |_|
        salsa20_hash_function(&dummy_ctx);

    var serialized_result: [SALSA20_BLOCK_SIZE]u8 = undefined;
    salsa20_serialize(SALSA20_BLOCK_WORDS, dummy_ctx.state[0..], serialized_result[0..]);

    try testing.expectEqualSlices(u8, reference, serialized_result[0..]);
}

// https://cr.yp.to/snuffle/spec.pdf
test "Salsa20 hash function" {
    try test_hash_function(1, &std.mem.zeroes([SALSA20_BLOCK_SIZE]u8), &std.mem.zeroes([SALSA20_BLOCK_SIZE]u8));
    try test_hash_function(1, &.{
        211, 159, 13,  115, 76, 55,  82,  183, 3,   117, 222, 37,  191, 187, 234, 136,
        49,  237, 179, 48,  1,  106, 178, 219, 175, 199, 166, 48,  86,  16,  179, 207,
        31,  240, 32,  63,  15, 83,  93,  161, 116, 147, 48,  113, 238, 55,  204, 36,
        79,  201, 235, 79,  3,  81,  156, 47,  203, 26,  244, 243, 88,  118, 104, 54,
    }, &.{
        109, 42,  178, 168, 156, 240, 248, 238, 168, 196, 190, 203, 26,  110, 170, 154,
        29,  29,  150, 26,  150, 30,  235, 249, 190, 163, 251, 48,  69,  144, 51,  57,
        118, 40,  152, 157, 180, 57,  27,  94,  107, 42,  236, 35,  27,  111, 114, 114,
        219, 236, 232, 135, 111, 155, 110, 18,  24,  232, 95,  158, 179, 19,  48,  202,
    });
    try test_hash_function(1, &.{
        88,  118, 104, 54,  79,  201, 235, 79,  3,  81,  156, 47,  203, 26,  244, 243,
        191, 187, 234, 136, 211, 159, 13,  115, 76, 55,  82,  183, 3,   117, 222, 37,
        86,  16,  179, 207, 49,  237, 179, 48,  1,  106, 178, 219, 175, 199, 166, 48,
        238, 55,  204, 36,  31,  240, 32,  63,  15, 83,  93,  161, 116, 147, 48,  113,
    }, &.{
        179, 19,  48,  202, 219, 236, 232, 135, 111, 155, 110, 18,  24,  232, 95,  158,
        26,  110, 170, 154, 109, 42,  178, 168, 156, 240, 248, 238, 168, 196, 190, 203,
        69,  144, 51,  57,  29,  29,  150, 26,  150, 30,  235, 249, 190, 163, 251, 48,
        27,  111, 114, 114, 118, 40,  152, 157, 180, 57,  27,  94,  107, 42,  236, 35,
    });
    try test_hash_function(1000000, &.{
        6,   124, 83,  146, 38,  191, 9,  50,  4,   161, 47,  222, 122, 182, 223, 185,
        75,  27,  0,   216, 16,  122, 7,  89,  162, 104, 101, 147, 213, 21,  54,  95,
        225, 253, 139, 176, 105, 132, 23, 116, 76,  41,  176, 207, 221, 34,  157, 108,
        94,  94,  99,  52,  90,  117, 91, 220, 146, 190, 239, 143, 196, 176, 130, 186,
    }, &.{
        8,   18,  38,  199, 119, 76,  215, 67,  173, 127, 144, 162, 103, 212, 176, 217,
        192, 19,  233, 33,  159, 197, 154, 160, 128, 243, 219, 65,  171, 136, 135, 225,
        123, 11,  68,  86,  237, 82,  20,  155, 133, 189, 9,   83,  167, 116, 194, 78,
        122, 127, 195, 185, 185, 204, 188, 90,  245, 9,   183, 248, 226, 85,  245, 104,
    });
}

// https://cr.yp.to/snuffle/spec.pdf
test "Salsa20 expansion function" {
    const key1 = [SALSA20_KEY_SIZE]u8{
        1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  15,  16,
        201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216,
    };
    const nonce1 = [SALSA20_NONCE_SIZE]u8{ 101, 102, 103, 104, 105, 106, 107, 108 };
    const pos1 = [SALSA20_NONCE_SIZE]u8{ 109, 110, 111, 112, 113, 114, 115, 116 };
    const reference1 = [SALSA20_BLOCK_SIZE]u8{
        69,  37,  68,  39,  41,  15,  107, 193, 255, 139, 122, 6,   170, 233, 217, 98,
        89,  144, 182, 106, 21,  51,  200, 65,  239, 49,  222, 34,  215, 114, 40,  126,
        104, 197, 7,   225, 197, 153, 31,  2,   102, 78,  76,  176, 84,  245, 246, 184,
        177, 160, 133, 130, 6,   72,  149, 119, 192, 195, 132, 236, 234, 103, 246, 74,
    };

    var ctx1 = salsa20_new(&key1, &nonce1, &pos1, &SALSA20_256_CONSTANTS);
    defer salsa20_destroy(&ctx1);

    var keystream_buffer: [SALSA20_BLOCK_SIZE]u8 = undefined;
    salsa20_serialize(SALSA20_BLOCK_WORDS, ctx1.state[0..], keystream_buffer[0..]);

    try testing.expectEqualSlices(u8, reference1[0..], keystream_buffer[0..]);

    const key2 = [SALSA20_KEY_SIZE]u8{
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    };
    const reference2 = [SALSA20_BLOCK_SIZE]u8{
        39,  173, 46,  248, 30,  200, 82,  17,  48,  67, 254, 239, 37,  18,  13,  247,
        241, 200, 61,  144, 10,  55,  50,  185, 6,   47, 246, 253, 143, 86,  187, 225,
        134, 85,  110, 246, 161, 163, 43,  235, 231, 94, 171, 51,  145, 214, 112, 29,
        14,  232, 5,   16,  151, 140, 183, 141, 171, 9,  122, 181, 104, 182, 177, 193,
    };

    var ctx2 = salsa20_new(&key2, &nonce1, &pos1, &SALSA20_128_CONSTANTS);
    defer salsa20_destroy(&ctx2);

    salsa20_serialize(SALSA20_BLOCK_WORDS, ctx2.state[0..], keystream_buffer[0..]);
    try testing.expectEqualSlices(u8, reference2[0..], keystream_buffer[0..]);
}

test "Salsa20 encryption" {
    const key = [SALSA20_KEY_SIZE]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const nonce = [SALSA20_NONCE_SIZE]u8{
        0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    };
    const counter = word_to_bytes_le(0) ++ word_to_bytes_le(0);
    const plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const reference = [_]u8{
        0x13, 0xfc, 0x5e, 0x28, 0x51, 0xf0, 0x79, 0x9d, 0x97, 0x52, 0x1b, 0xa6, 0xa9, 0x37, 0x11, 0x87,
        0x00, 0x95, 0x7c, 0x2e, 0xf9, 0x96, 0xe4, 0x2c, 0x59, 0x84, 0x9d, 0x45, 0x0c, 0x6e, 0xa2, 0x2e,
        0x91, 0xcd, 0xcc, 0xea, 0x39, 0x1e, 0xe0, 0xa3, 0x57, 0xbb, 0x56, 0xcd, 0xf5, 0x2c, 0x56, 0xce,
        0x01, 0x38, 0x07, 0xa9, 0x45, 0xb9, 0x17, 0xee, 0x6c, 0xcb, 0x18, 0xce, 0xca, 0xbe, 0x4b, 0xf4,
        0x09, 0xba, 0x72, 0xfb, 0xdf, 0x90, 0xdb, 0x02, 0x8d, 0x22, 0x61, 0x7f, 0x1c, 0xa9, 0x84, 0x15,
        0x6c, 0xa2, 0x72, 0x47, 0x3a, 0xf4, 0xf0, 0xe4, 0xcb, 0x3d, 0x85, 0x8b, 0x7a, 0xb4, 0x67, 0xae,
        0x14, 0x71, 0x87, 0xab, 0xac, 0xb7, 0xc6, 0xe9, 0xaf, 0x6f, 0x2f, 0x47, 0x28, 0x7e, 0x2e, 0x0c,
        0xb3, 0x18,
    };

    var ctx = salsa20_new(&key, &nonce, &counter, &SALSA20_256_CONSTANTS);
    defer salsa20_destroy(&ctx);

    var buffer: [plaintext.len]u8 = undefined;
    @memcpy(&buffer, plaintext);

    try salsa20_encrypt_inplace(&ctx, &buffer);
    try testing.expectEqualSlices(u8, reference[0..], buffer[0..]);
}
