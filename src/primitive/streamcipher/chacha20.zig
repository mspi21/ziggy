const std = @import("std");
const testing = std.testing;

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

// ----------------------------------- ENCRYPTION/DECRYPTION -----------------------------------  //

pub const ChaCha20Ctx = struct {
    key: [CHACHA20_KEY_WORDS]u32,
    nonce: [CHACHA20_NONCE_WORDS]u32,
    state: [CHACHA20_BLOCK_WORDS]u32,
    working_state: [CHACHA20_BLOCK_WORDS]u32,
    keystream_idx: u6,
};

pub fn chacha20_new(
    key: *const [CHACHA20_KEY_SIZE]u8,
    counter_size: comptime_int,
    counter: *const [counter_size]u8,
    nonce_size: comptime_int,
    nonce: *const [nonce_size]u8,
) ChaCha20Ctx {
    if (comptime counter_size + nonce_size != CHACHA20_NONCE_SIZE)
        @panic("Invalid ChaCha initialization: The size of counter and nonce must add up to 16 bytes.");

    var ctx = ChaCha20Ctx{
        .key = undefined,
        .nonce = undefined,
        .state = undefined,
        .working_state = undefined,
        .keystream_idx = undefined,
    };

    const counter_words = comptime counter_size / 4;
    const nonce_words = comptime nonce_size / 4;

    chacha20_deserialize(CHACHA20_KEY_WORDS, key, &ctx.key);
    chacha20_deserialize(counter_words, counter, ctx.nonce[0..counter_words]);
    chacha20_deserialize(nonce_words, nonce, ctx.nonce[counter_words .. counter_words + nonce_words]);

    chacha20_block_function(&ctx);
    ctx.keystream_idx = 0;

    return ctx;
}

pub fn chacha20_destroy(ctx: *ChaCha20Ctx) void {
    @memset(ctx.state, 0);
    @memset(ctx.key, 0);
    @memset(ctx.nonce, 0);
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

pub fn chacha20_quarter_round(
    state: *[CHACHA20_BLOCK_WORDS]u32,
    ia: u8,
    ib: u8,
    ic: u8,
    id: u8,
) void {
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
    // 0xe0, 0x31, 0x95, 0x87, 0x7d, 0xf3, 0xec, 0xc5, 0xb1, 0x61, 0x64, 0x51, 0x8a, 0x2f, 0xa6, 0xc9,
    // 0xf3, 0x0e, 0xc2, 0x44, 0x7f, 0xaf, 0x90, 0x33, 0x0b, 0x69, 0xfc, 0xd9, 0x4c, 0x71, 0x5f, 0x2a,
    // 0x67, 0x27, 0x37, 0x53, 0x31, 0x56, 0x0a, 0xb0, 0x1a, 0x54, 0x4c, 0x97, 0x63, 0x99, 0x9e, 0x35,
    // 0x61, 0x10, 0x97, 0x5c, 0x89, 0x16, 0x63, 0x3d, 0xd6, 0xd9, 0x98, 0x20, 0x20, 0xd3, 0xdb, 0x91,

    const reference = [CHACHA20_BLOCK_WORDS]u32{
        0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
        0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
        0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
        0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320,
    };
    // 0xe0, 0x31, 0x95, 0x87, 0x7d, 0xf3, 0xec, 0xc5, 0xdc, 0x86, 0xb8, 0xbd, 0x8a, 0x2f, 0xa6, 0xc9,
    // 0xf3, 0x0e, 0xc2, 0x44, 0x7f, 0xaf, 0x90, 0x33, 0x0b, 0x69, 0xfc, 0xd9, 0xd2, 0xaf, 0xac, 0xcf,
    // 0x80, 0xea, 0x6b, 0xe4, 0x31, 0x56, 0x0a, 0xb0, 0x1a, 0x54, 0x4c, 0x97, 0x63, 0x99, 0x9e, 0x35,
    // 0x61, 0x10, 0x97, 0x5c, 0x79, 0x7c, 0xc0, 0xcc, 0xd6, 0xd9, 0x98, 0x20, 0x20, 0xd3, 0xdb, 0x91,

    chacha20_quarter_round(&state, 2, 7, 8, 13);
    try testing.expectEqualSlices(u32, reference[0..], state[0..]);
}

// https://www.rfc-editor.org/rfc/rfc7539#section-2.3.2
test "ChaCha20 Block Function" {
    var chacha = chacha20_rfc7539_new(
        &.{
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        },
        &.{ 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00 },
        &.{ 0x01, 0x00, 0x00, 0x00 },
    );
    const reference = [CHACHA20_BLOCK_SIZE]u8{
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
    };

    chacha20_block_function(&chacha);

    var buffer: [CHACHA20_BLOCK_SIZE]u8 = undefined;
    chacha20_serialize(CHACHA20_BLOCK_WORDS, &chacha.state, &buffer);

    try testing.expectEqualSlices(u8, reference[0..], buffer[0..]);
}
