const std = @import("std");
const testing = std.testing;

// ----------------------------------- ERROR DEFINITIONS -----------------------------------  //

const KeyStreamDepleted = error.KeyStreamDepleted;

// ----------------------------------- ChaCha20 CONSTANTS -----------------------------------  //

const CHACHA20_BLOCK_SIZE = 512 / 8;
const CHACHA20_BLOCK_WORDS = CHACHA20_BLOCK_SIZE / 4;

const CHACHA20_KEY_SIZE = 256 / 8;
const CHACHA20_KEY_WORDS = CHACHA20_KEY_SIZE / 4;

const CHACHA20_NONCE_SIZE = 128 / 8;
const CHACHA20_NONCE_WORDS = CHACHA20_NONCE_SIZE / 4;

const CHACHA20_CONSTANTS = [128 / 8 / 4]u32{
    bytes_to_word_le("expa"),
    bytes_to_word_le("nd 3"),
    bytes_to_word_le("2-by"),
    bytes_to_word_le("te k"),
};

pub const ChaCha20_Bernstein_Parameters = struct {
    pub const NONCE_SIZE = 64 / 8;
    pub const COUNTER_SIZE = 64 / 8;
};

pub const ChaCha20_RFC7539_Parameters = struct {
    pub const NONCE_SIZE = 96 / 8;
    pub const COUNTER_SIZE = 32 / 8;
};

// ----------------------------------- CONTEXT MANAGEMENT -----------------------------------  //

pub const ChaCha20Ctx = struct {
    key: [CHACHA20_KEY_WORDS]u32,
    nonce: [CHACHA20_NONCE_WORDS]u32,
    state: [CHACHA20_BLOCK_WORDS]u32,
    working_state: [CHACHA20_BLOCK_WORDS]u32,
    counter_idx_lsw: u8,
    counter_idx_msw: u8,
    keystream_idx: u8,
};

pub fn chacha20_new(
    key: *const [CHACHA20_KEY_SIZE]u8,
    counter_size: comptime_int,
    counter: *const [counter_size]u8,
    nonce_size: comptime_int,
    nonce: *const [nonce_size]u8,
) ChaCha20Ctx {
    if (comptime counter_size + nonce_size != CHACHA20_NONCE_SIZE)
        @panic("Invalid ChaCha initialization: The lengths of the counter and nonce must add up to 16 bytes.");

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

    chacha20_deserialize(CHACHA20_KEY_WORDS, key, &ctx.key);
    chacha20_deserialize(counter_words, counter, ctx.nonce[0..counter_words]);
    chacha20_deserialize(nonce_words, nonce, ctx.nonce[counter_words .. counter_words + nonce_words]);

    chacha20_block_function(&ctx);
    ctx.keystream_idx = 0;

    return ctx;
}

pub fn chacha20_destroy(ctx: *ChaCha20Ctx) void {
    @memset(&ctx.state, 0);
    @memset(&ctx.key, 0);
    @memset(&ctx.nonce, 0);
    ctx.keystream_idx = 0;
}

pub fn chacha20_bernstein_new(
    key: *const [CHACHA20_KEY_SIZE]u8,
    nonce: *const [ChaCha20_Bernstein_Parameters.NONCE_SIZE]u8,
    counter: *const [ChaCha20_Bernstein_Parameters.COUNTER_SIZE]u8,
) ChaCha20Ctx {
    return chacha20_new(
        key,
        ChaCha20_Bernstein_Parameters.COUNTER_SIZE,
        counter,
        ChaCha20_Bernstein_Parameters.NONCE_SIZE,
        nonce,
    );
}

pub fn chacha20_rfc7539_new(
    key: *const [CHACHA20_KEY_SIZE]u8,
    nonce: *const [ChaCha20_RFC7539_Parameters.NONCE_SIZE]u8,
    counter: *const [ChaCha20_RFC7539_Parameters.COUNTER_SIZE]u8,
) ChaCha20Ctx {
    return chacha20_new(
        key,
        ChaCha20_RFC7539_Parameters.COUNTER_SIZE,
        counter,
        ChaCha20_RFC7539_Parameters.NONCE_SIZE,
        nonce,
    );
}

// ----------------------------------- ENCRYPTION/DECRYPTION -----------------------------------  //

pub fn chacha20_encrypt_inplace(ctx: *ChaCha20Ctx, plaintext: []u8) !void {
    for (0..plaintext.len) |i| {
        try chacha20_ensure_keystream_expanded(ctx);
        const keystream: [*]const u8 = @ptrCast(&ctx.state);

        plaintext[i] ^= keystream[ctx.keystream_idx];
        ctx.keystream_idx += 1;
    }
}

pub fn chacha20_decrypt_inplace(ctx: *ChaCha20Ctx, ciphertext: []u8) !void {
    return chacha20_encrypt_inplace(ctx, ciphertext);
}

fn chacha20_ensure_keystream_expanded(ctx: *ChaCha20Ctx) !void {
    if (ctx.keystream_idx == CHACHA20_BLOCK_SIZE) {
        try chacha20_increment_counter(ctx);
        chacha20_block_function(ctx);
        ctx.keystream_idx = 0;
    }
}

fn chacha20_increment_counter(ctx: *ChaCha20Ctx) !void {
    for (ctx.counter_idx_lsw..ctx.counter_idx_msw + 1) |idx| {
        const ov = @addWithOverflow(ctx.nonce[idx], 1);
        ctx.nonce[idx] = ov[0];

        if (ov[1] == 0)
            return;
    }
    return KeyStreamDepleted;
}

// ----------------------------------- KEYSTREAM EXPANSION -----------------------------------  //

pub fn chacha20_quarter_round(state: *[CHACHA20_BLOCK_WORDS]u32, ia: u8, ib: u8, ic: u8, id: u8) void {
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

pub fn chacha20_inner_block(state: *[CHACHA20_BLOCK_WORDS]u32) void {
    chacha20_quarter_round(state, 0, 4, 8, 12);
    chacha20_quarter_round(state, 1, 5, 9, 13);
    chacha20_quarter_round(state, 2, 6, 10, 14);
    chacha20_quarter_round(state, 3, 7, 11, 15);
    chacha20_quarter_round(state, 0, 5, 10, 15);
    chacha20_quarter_round(state, 1, 6, 11, 12);
    chacha20_quarter_round(state, 2, 7, 8, 13);
    chacha20_quarter_round(state, 3, 4, 9, 14);
}

pub fn chacha20_block_function(ctx: *ChaCha20Ctx) void {
    // Reset state.
    {
        comptime var i = 0;

        @memcpy(ctx.state[i .. i + CHACHA20_CONSTANTS.len], &CHACHA20_CONSTANTS);
        i += CHACHA20_CONSTANTS.len;

        @memcpy(ctx.state[i .. i + CHACHA20_KEY_WORDS], ctx.key[0..]);
        i += CHACHA20_KEY_WORDS;

        @memcpy(ctx.state[i .. i + CHACHA20_NONCE_WORDS], ctx.nonce[0..]);
        i += CHACHA20_NONCE_WORDS;

        if (comptime i != CHACHA20_BLOCK_WORDS)
            @panic("Invalid ChaCha20 parameters: |constants + key + nonce + counter| != block_size!");
    }

    // Copy state to working_state.
    @memcpy(&ctx.working_state, &ctx.state);

    // Perform all 20 rounds (10 column rounds and 10 diagonal rounds).
    for (0..10) |_| {
        chacha20_inner_block(&ctx.working_state);
    }

    // Add the working_state to the state.
    for (0..CHACHA20_BLOCK_WORDS) |i| {
        ctx.state[i] +%= ctx.working_state[i];
    }
}

// ----------------------------------- LITTLE ENDIAN HELPERS -----------------------------------  //

fn chacha20_serialize(L: comptime_int, words: *const [L]u32, bytes: *[L * 4]u8) void {
    if (comptime @import("builtin").target.cpu.arch.endian() == .little) {
        @memcpy(bytes, @as(*const [L * 4]u8, @ptrCast(words)));
    } else {
        var tmp: [4]u8 = undefined;
        for (0..L) |i| {
            tmp = word_to_bytes_le(words[i]);
            bytes[i * 4] = tmp[0];
            bytes[i * 4 + 1] = tmp[1];
            bytes[i * 4 + 2] = tmp[2];
            bytes[i * 4 + 3] = tmp[3];
        }
    }
}

fn chacha20_deserialize(L: comptime_int, bytes: *const [L * 4]u8, words: *[L]u32) void {
    if (comptime @import("builtin").target.cpu.arch.endian() == .little) {
        @memcpy(@as(*[L * 4]u8, @ptrCast(words)), bytes);
    } else {
        for (0..L) |i| {
            words[i] = bytes_to_word_le(@ptrCast(bytes[(i * 4)..(i * 4 + 4)]));
        }
    }
}

fn bytes_to_word_le(bytes: *const [4]u8) u32 {
    return (@as(u32, bytes[3]) << 24) | (@as(u32, bytes[2]) << 16) | (@as(u32, bytes[1]) << 8) | @as(u32, bytes[0]);
}

fn word_to_bytes_le(word: u32) [4]u8 {
    var bytes: [4]u8 = undefined;
    bytes[3] = @truncate(word >> 24);
    bytes[2] = @truncate(word >> 16);
    bytes[1] = @truncate(word >> 8);
    bytes[0] = @truncate(word);
    return bytes;
}

// ----------------------------------- GENERIC HELPERS -----------------------------------  //

fn rol(word: u32, bits: comptime_int) u32 {
    return word << bits | word >> (32 - bits);
}

// ----------------------------------- TEST VECTORS -----------------------------------  //

// https://www.rfc-editor.org/rfc/rfc7539#section-2.2.1
test "ChaCha Quarter Round" {
    var state = [CHACHA20_BLOCK_WORDS]u32{
        0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
        0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
        0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
        0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320,
    };
    const reference = [CHACHA20_BLOCK_WORDS]u32{
        0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
        0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
        0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
        0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320,
    };

    chacha20_quarter_round(&state, 2, 7, 8, 13);
    try testing.expectEqualSlices(u32, reference[0..], state[0..]);
}

// https://www.rfc-editor.org/rfc/rfc7539#section-2.3.2
test "ChaCha20 Block Function" {
    const key = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const nonce = [_]u8{
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    };

    const reference = [CHACHA20_BLOCK_SIZE]u8{
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
    };

    var chacha = chacha20_rfc7539_new(&key, &nonce, &word_to_bytes_le(1));
    defer chacha20_destroy(&chacha);

    chacha20_block_function(&chacha);

    var buffer: [CHACHA20_BLOCK_SIZE]u8 = undefined;
    chacha20_serialize(CHACHA20_BLOCK_WORDS, &chacha.state, &buffer);

    try testing.expectEqualSlices(u8, reference[0..], buffer[0..]);
}

// https://www.rfc-editor.org/rfc/rfc7539#section-2.4.2
test "ChaCha20 Cipher" {
    const key = [CHACHA20_KEY_SIZE]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const nonce = [ChaCha20_RFC7539_Parameters.NONCE_SIZE]u8{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    };
    const counter = word_to_bytes_le(1);
    const plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const reference = [_]u8{
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d,
    };

    var chacha = chacha20_rfc7539_new(&key, &nonce, &counter);
    defer chacha20_destroy(&chacha);

    var buffer: [plaintext.len]u8 = undefined;
    @memcpy(&buffer, plaintext);

    try chacha20_encrypt_inplace(&chacha, &buffer);
    try testing.expectEqualSlices(u8, reference[0..], buffer[0..]);
}
