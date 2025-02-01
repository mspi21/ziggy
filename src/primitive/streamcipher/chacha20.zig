const std = @import("std");
const testing = std.testing;

const byte_operations = @import("TODO").utility.byte_operations;
const word_to_bytes = byte_operations.word_to_bytes_le;
const bytes_to_word = byte_operations.bytes_to_word_le;

// ----------------------------------- ERROR DEFINITIONS -----------------------------------  //

pub const KeyStreamDepleted = error.KeyStreamDepleted;

// ----------------------------------- ChaCha20 CONSTANTS -----------------------------------  //

pub const BLOCK_SIZE = 512 / 8;
pub const BLOCK_WORDS = BLOCK_SIZE / 4;

pub const KEY_SIZE = 256 / 8;
pub const KEY_WORDS = KEY_SIZE / 4;

pub const NONCE_SIZE = 128 / 8;
pub const NONCE_WORDS = NONCE_SIZE / 4;

pub const Parameters_Bernstein = struct {
    pub const NONCE_SIZE = 64 / 8;
    pub const COUNTER_SIZE = 64 / 8;
};

pub const Parameters_RFC7539 = struct {
    pub const NONCE_SIZE = 96 / 8;
    pub const COUNTER_SIZE = 32 / 8;
};

const CONSTANTS = [128 / 8 / 4]u32{
    bytes_to_word("expa"),
    bytes_to_word("nd 3"),
    bytes_to_word("2-by"),
    bytes_to_word("te k"),
};

// ----------------------------------- CONTEXT MANAGEMENT -----------------------------------  //

pub const ChaCha20Ctx = struct {
    key: [KEY_WORDS]u32,
    nonce: [NONCE_WORDS]u32,
    state: [BLOCK_WORDS]u32,
    working_state: [BLOCK_WORDS]u32,
    counter_idx_lsw: u8,
    counter_idx_msw: u8,
    keystream_idx: u8,
};

pub fn chacha20_new(
    key: *const [KEY_SIZE]u8,
    counter_size: comptime_int,
    counter: *const [counter_size]u8,
    nonce_size: comptime_int,
    nonce: *const [nonce_size]u8,
) ChaCha20Ctx {
    if (comptime counter_size + nonce_size != NONCE_SIZE)
        @compileError("Invalid ChaCha initialization: The lengths of the counter and nonce must add up to 16 bytes.");

    const counter_words = comptime counter_size / 4;
    const nonce_words = comptime nonce_size / 4;

    var ctx = ChaCha20Ctx{
        .key = undefined,
        .nonce = undefined,
        .state = undefined,
        .working_state = undefined,
        .counter_idx_lsw = 0,
        .counter_idx_msw = counter_words - 1,
        .keystream_idx = undefined,
    };

    deserialize(KEY_WORDS, key, &ctx.key);
    deserialize(counter_words, counter, ctx.nonce[0..counter_words]);
    deserialize(nonce_words, nonce, ctx.nonce[counter_words .. counter_words + nonce_words]);

    block_function(&ctx);
    ctx.keystream_idx = 0;

    return ctx;
}

pub fn chacha20_destroy(ctx: *ChaCha20Ctx) void {
    @memset(&ctx.key, 0);
    @memset(&ctx.nonce, 0);
    @memset(&ctx.state, 0);
    @memset(&ctx.working_state, 0);
    ctx.keystream_idx = 0;
}

pub fn chacha20_bernstein_new(
    key: *const [KEY_SIZE]u8,
    nonce: *const [Parameters_Bernstein.NONCE_SIZE]u8,
    counter: *const [Parameters_Bernstein.COUNTER_SIZE]u8,
) ChaCha20Ctx {
    return chacha20_new(
        key,
        Parameters_Bernstein.COUNTER_SIZE,
        counter,
        Parameters_Bernstein.NONCE_SIZE,
        nonce,
    );
}

pub fn chacha20_rfc7539_new(
    key: *const [KEY_SIZE]u8,
    nonce: *const [Parameters_RFC7539.NONCE_SIZE]u8,
    counter: *const [Parameters_RFC7539.COUNTER_SIZE]u8,
) ChaCha20Ctx {
    return chacha20_new(
        key,
        Parameters_RFC7539.COUNTER_SIZE,
        counter,
        Parameters_RFC7539.NONCE_SIZE,
        nonce,
    );
}

// ----------------------------------- ENCRYPTION/DECRYPTION -----------------------------------  //

pub fn encrypt_inplace(ctx: *ChaCha20Ctx, plaintext: []u8) !void {
    for (0..plaintext.len) |i| {
        try ensure_keystream_expanded(ctx);
        const keystream: [*]const u8 = @ptrCast(&ctx.state);

        plaintext[i] ^= keystream[ctx.keystream_idx];
        ctx.keystream_idx += 1;
    }
}

pub fn decrypt_inplace(ctx: *ChaCha20Ctx, ciphertext: []u8) !void {
    return encrypt_inplace(ctx, ciphertext);
}

pub fn ensure_keystream_expanded(ctx: *ChaCha20Ctx) !void {
    if (ctx.keystream_idx == BLOCK_SIZE) {
        try increment_counter(ctx);
        block_function(ctx);
        ctx.keystream_idx = 0;
    }
}

pub fn increment_counter(ctx: *ChaCha20Ctx) !void {
    for (ctx.counter_idx_lsw..ctx.counter_idx_msw + 1) |idx| {
        const ov = @addWithOverflow(ctx.nonce[idx], 1);
        ctx.nonce[idx] = ov[0];

        if (ov[1] == 0)
            return;
    }
    return KeyStreamDepleted;
}

// ----------------------------------- KEYSTREAM EXPANSION -----------------------------------  //

pub fn quarter_round(state: *[BLOCK_WORDS]u32, ia: u8, ib: u8, ic: u8, id: u8) void {
    var a = state[ia];
    var b = state[ib];
    var c = state[ic];
    var d = state[id];

    a +%= b;
    d ^= a;
    d = rol(d, 16);
    c +%= d;
    b ^= c;
    b = rol(b, 12);
    a +%= b;
    d ^= a;
    d = rol(d, 8);
    c +%= d;
    b ^= c;
    b = rol(b, 7);

    state[ia] = a;
    state[ib] = b;
    state[ic] = c;
    state[id] = d;
}

pub fn double_round(state: *[BLOCK_WORDS]u32) void {
    quarter_round(state, 0, 4, 8, 12);
    quarter_round(state, 1, 5, 9, 13);
    quarter_round(state, 2, 6, 10, 14);
    quarter_round(state, 3, 7, 11, 15);
    quarter_round(state, 0, 5, 10, 15);
    quarter_round(state, 1, 6, 11, 12);
    quarter_round(state, 2, 7, 8, 13);
    quarter_round(state, 3, 4, 9, 14);
}

pub fn block_function(ctx: *ChaCha20Ctx) void {
    // Reset state.
    {
        comptime var i = 0;

        @memcpy(ctx.state[i .. i + CONSTANTS.len], &CONSTANTS);
        i += CONSTANTS.len;

        @memcpy(ctx.state[i .. i + KEY_WORDS], ctx.key[0..]);
        i += KEY_WORDS;

        @memcpy(ctx.state[i .. i + NONCE_WORDS], ctx.nonce[0..]);
        i += NONCE_WORDS;

        if (comptime i != BLOCK_WORDS)
            @compileError("Invalid ChaCha20 parameters: |constants + key + nonce + counter| != block_size.");
    }

    // Copy state to working_state.
    @memcpy(&ctx.working_state, &ctx.state);

    // Perform all 20 rounds (10 column rounds and 10 diagonal rounds).
    for (0..10) |_|
        double_round(&ctx.working_state);

    // Add the working_state to the state.
    for (0..BLOCK_WORDS) |i|
        ctx.state[i] +%= ctx.working_state[i];
}

// ----------------------------------- HELPERS -----------------------------------  //

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
