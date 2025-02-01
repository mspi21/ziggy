const std = @import("std");
const testing = std.testing;

const byte_operations = @import("utility").byte_operations;
const bytes_to_word = byte_operations.bytes_to_word_le;
const word_to_bytes = byte_operations.word_to_bytes_le;

// ----------------------------------- ERROR DEFINITIONS ----------------------------------- //

pub const KeyStreamDepleted = error.KeyStreamDepleted;

// ----------------------------------- ChaCha20 CONSTANTS ----------------------------------- //

pub const BLOCK_SIZE = 512 / 8;
pub const BLOCK_WORDS = BLOCK_SIZE / 4;

pub const KEY_SIZE = 256 / 8;
pub const KEY_WORDS = KEY_SIZE / 4;
pub const KEY_SIZE_128 = 128 / 8;
pub const KEY_WORDS_128 = KEY_SIZE_128 / 4;

pub const NONCE_SIZE = 64 / 8;
pub const NONCE_WORDS = NONCE_SIZE / 4;

pub const COUNTER_SIZE = 64 / 8;
pub const COUNTER_WORDS = COUNTER_SIZE / 4;

pub const CONSTANT_WORDS = 128 / 8 / 4;

pub const CONSTANTS_256 = [CONSTANT_WORDS]u32{
    bytes_to_word("expa"),
    bytes_to_word("nd 3"),
    bytes_to_word("2-by"),
    bytes_to_word("te k"),
};
pub const CONSTANTS_128 = [CONSTANT_WORDS]u32{
    bytes_to_word("expa"),
    bytes_to_word("nd 1"),
    bytes_to_word("6-by"),
    bytes_to_word("te k"),
};

// ----------------------------------- CONTEXT MANAGEMENT ----------------------------------- //

pub const Salsa20Ctx = struct {
    key: [KEY_WORDS]u32,
    nonce: [NONCE_WORDS]u32,
    counter: [COUNTER_WORDS]u32,
    constants: [CONSTANT_WORDS]u32,
    state: [BLOCK_WORDS]u32,
    working_state: [BLOCK_WORDS]u32,
    keystream_idx: u8,
};

pub fn salsa20_new(
    key: *const [KEY_SIZE]u8,
    nonce: *const [NONCE_SIZE]u8,
    counter: *const [COUNTER_SIZE]u8,
    constants: *const [CONSTANT_WORDS]u32,
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

    deserialize(KEY_WORDS, key, &ctx.key);
    deserialize(COUNTER_WORDS, counter, &ctx.counter);
    deserialize(NONCE_WORDS, nonce, &ctx.nonce);
    @memcpy(&ctx.constants, constants);

    block_function(&ctx);
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

// ----------------------------------- ENCRYPTION/DECRYPTION ----------------------------------- //

pub fn encrypt_inplace(ctx: *Salsa20Ctx, plaintext: []u8) !void {
    for (0..plaintext.len) |i| {
        try ensure_keystream_expanded(ctx);
        const keystream: [*]const u8 = @ptrCast(&ctx.state);

        plaintext[i] ^= keystream[ctx.keystream_idx];
        ctx.keystream_idx += 1;
    }
}

pub fn decrypt_inplace(ctx: *Salsa20Ctx, ciphertext: []u8) !void {
    return encrypt_inplace(ctx, ciphertext);
}

pub fn ensure_keystream_expanded(ctx: *Salsa20Ctx) !void {
    if (ctx.keystream_idx == BLOCK_SIZE) {
        try increment_counter(ctx);
        block_function(ctx);
        ctx.keystream_idx = 0;
    }
}

pub fn increment_counter(ctx: *Salsa20Ctx) !void {
    for (0..COUNTER_WORDS) |idx| {
        const ov = @addWithOverflow(ctx.counter[idx], 1);
        ctx.counter[idx] = ov[0];

        if (ov[1] == 0)
            return;
    }
    return KeyStreamDepleted;
}

// ----------------------------------- KEYSTREAM EXPANSION ----------------------------------- //

pub fn quarter_round(state: *[BLOCK_WORDS]u32, ia: u8, ib: u8, ic: u8, id: u8) void {
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

pub fn column_round(state: *[BLOCK_WORDS]u32) void {
    quarter_round(state, 0, 4, 8, 12);
    quarter_round(state, 5, 9, 13, 1);
    quarter_round(state, 10, 14, 2, 6);
    quarter_round(state, 15, 3, 7, 11);
}

pub fn row_round(state: *[BLOCK_WORDS]u32) void {
    quarter_round(state, 0, 1, 2, 3);
    quarter_round(state, 5, 6, 7, 4);
    quarter_round(state, 10, 11, 8, 9);
    quarter_round(state, 15, 12, 13, 14);
}

pub fn double_round(state: *[BLOCK_WORDS]u32) void {
    column_round(state);
    row_round(state);
}

pub fn hash_function(ctx: *Salsa20Ctx) void {
    // Copy state to working_state.
    @memcpy(&ctx.working_state, &ctx.state);

    // Perform all 20 rounds (10 row and 10 column rounds).
    for (0..10) |_| {
        double_round(&ctx.working_state);
    }

    // Add the working_state to the state.
    for (0..BLOCK_WORDS) |i| {
        ctx.state[i] +%= ctx.working_state[i];
    }
}

pub fn block_function(ctx: *Salsa20Ctx) void {
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
    hash_function(ctx);
}

// ----------------------------------- HELPERS ----------------------------------- //

pub fn serialize(L: comptime_int, words: *const [L]u32, bytes: *[L * 4]u8) void {
    for (0..L) |i|
        std.mem.writeInt(u32, @ptrCast(bytes[(i * 4)..(i * 4 + 4)]), words[i], .little);
}

pub fn deserialize(L: comptime_int, bytes: *const [L * 4]u8, words: *[L]u32) void {
    for (0..L) |i|
        words[i] = std.mem.readInt(u32, @ptrCast(bytes[(i * 4)..(i * 4 + 4)]), .little);
}

fn rol(word: u32, bits: comptime_int) u32 {
    return word << bits | word >> (32 - bits);
}
