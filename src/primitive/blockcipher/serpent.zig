const std = @import("std");
const testing = std.testing;

const byte_operations = @import("utility").byte_operations;
const word_to_bytes = byte_operations.word_to_bytes_le;
const bytes_to_word = byte_operations.bytes_to_word_le;

const CryptoError = error{
    InvalidKeyLength,
};

// ----------------------------------- CONSTANTS ----------------------------------- //

pub const BLOCK_SIZE = 128 / 8;

pub const KEY_SIZE_128 = 128 / 8;
pub const KEY_SIZE_192 = 192 / 8;
pub const KEY_SIZE_256 = 256 / 8;

pub const MAX_KEY_SIZE = KEY_SIZE_256;

const N_ROUNDS = 32;
const SUBKEY_COUNT = N_ROUNDS + 1;

const SBOXES = [_][16]u8{
    .{ 3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12 }, // S0
    .{ 15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4 }, // S1
    .{ 8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2 }, // S2
    .{ 0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14 }, // S3
    .{ 1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13 }, // S4
    .{ 15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1 }, // S5
    .{ 7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0 }, // S6
    .{ 1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6 }, // S7
};

const PHI_FRAC: u32 = 0x9e3779b9;

// ----------------------------------- KEY EXPANSION ----------------------------------- //

pub fn expand_key(key: []const u8) ![SUBKEY_COUNT][BLOCK_SIZE / 4]u32 {
    // Pad short keys to 256 bits.
    const full_key = try pad_user_key(key);

    // Prepare the prekey.
    var prekey: [140]u32 = undefined;
    @memcpy(prekey[0..8], full_key[0..]);

    for (0..132) |_j| {
        const j: u32 = @intCast(_j);
        const i: u32 = @intCast(j + 8);
        const tmp = prekey[i - 8] ^ prekey[i - 5] ^ prekey[i - 3] ^ prekey[i - 1] ^ PHI_FRAC ^ j;
        prekey[i] = (tmp << 11) | (tmp >> 21);
    }

    //for (0..SUBKEY_COUNT) |i| {
    //    std.debug.print("{d}: {x} {x} {x} {x}\n", .{
    //        i,
    //        prekey[8 + i * 4 + 0],
    //        prekey[8 + i * 4 + 1],
    //        prekey[8 + i * 4 + 2],
    //        prekey[8 + i * 4 + 3],
    //    });
    //}

    // Compute the subkeys.
    var subkeys: [SUBKEY_COUNT][BLOCK_SIZE / 4]u32 = undefined;
    var tmp: [4]u32 = undefined;

    inline for (0..SUBKEY_COUNT) |i| {
        sbox_bitslice(
            (32 + 3 - i) % 8,
            prekey[8 + i * 4 + 0],
            prekey[8 + i * 4 + 1],
            prekey[8 + i * 4 + 2],
            prekey[8 + i * 4 + 3],
            &tmp[0],
            &tmp[1],
            &tmp[2],
            &tmp[3],
        );
        subkeys[i] = tmp;
    }

    //for (0..SUBKEY_COUNT) |i| {
    //    std.debug.print("{d}: {x} {x} {x} {x}\n", .{ i, subkeys[i][0], subkeys[i][1], subkeys[i][2], subkeys[i][3] });
    //}

    return subkeys;
}

pub fn pad_user_key(key: []const u8) ![MAX_KEY_SIZE / 4]u32 {
    if (key.len > MAX_KEY_SIZE)
        return CryptoError.InvalidKeyLength;

    var long_key: [MAX_KEY_SIZE]u8 = undefined;
    @memcpy(long_key[0..key.len], key[0..]);
    if (key.len < MAX_KEY_SIZE) {
        long_key[key.len] = 0x01;
        @memset(long_key[key.len + 1 ..], 0x00);
    }

    //std.debug.print("{any}\n", .{long_key});

    var key_words: [MAX_KEY_SIZE / 4]u32 = undefined;
    inline for (0..MAX_KEY_SIZE / 4) |i|
        key_words[i] = bytes_to_word(@ptrCast(long_key[i * 4 .. (i + 1) * 4]));
    return key_words;
}

// ----------------------------------- ENCRYPTION ----------------------------------- //

pub fn encrypt_block(
    block_in: *const [BLOCK_SIZE]u8,
    block_out: *[BLOCK_SIZE]u8,
    key_schedule: *const [SUBKEY_COUNT][BLOCK_SIZE / 4]u32,
) void {
    var state = [BLOCK_SIZE / 4]u32{
        bytes_to_word(block_in[0..4]),
        bytes_to_word(block_in[4..8]),
        bytes_to_word(block_in[8..12]),
        bytes_to_word(block_in[12..16]),
    };

    // Apply all rounds but the last.
    inline for (0..N_ROUNDS - 1) |i| {
        add_round_key(&state, &key_schedule[i]);
        sbox_bitslice(
            i % 8,
            state[0],
            state[1],
            state[2],
            state[3],
            &state[0],
            &state[1],
            &state[2],
            &state[3],
        );
        linear_transformation(&state);
    }

    // Apply the last round.
    add_round_key(&state, &key_schedule[N_ROUNDS - 1]);
    sbox_bitslice(
        (N_ROUNDS - 1) % 8,
        state[0],
        state[1],
        state[2],
        state[3],
        &state[0],
        &state[1],
        &state[2],
        &state[3],
    );
    add_round_key(&state, &key_schedule[N_ROUNDS]);

    block_out.* = word_to_bytes(state[0]) ++ word_to_bytes(state[1]) ++ word_to_bytes(state[2]) ++ word_to_bytes(state[3]);
    std.crypto.utils.secureZero(u32, &state);
}

// ----------------------------------- COMMON OPERATIONS ----------------------------------- //

pub fn add_round_key(state: *[BLOCK_SIZE / 4]u32, subkey: *const [BLOCK_SIZE / 4]u32) void {
    for (0..state.len) |i|
        state[i] ^= subkey[i];
}

pub fn linear_transformation(state: *[BLOCK_SIZE / 4]u32) void {
    var x0 = state[0];
    var x1 = state[1];
    var x2 = state[2];
    var x3 = state[3];

    x0 = rol(x0, 13);
    x2 = rol(x2, 3);
    x1 ^= x0 ^ x2;
    x3 ^= (x0 << 3) ^ x2;
    x1 = rol(x1, 1);
    x3 = rol(x3, 7);
    x0 ^= x1 ^ x3;
    x2 ^= (x1 << 7) ^ x3;
    x0 = rol(x0, 5);
    x2 = rol(x2, 22);

    state[0] = x0;
    state[1] = x1;
    state[2] = x2;
    state[3] = x3;
}

pub fn sbox_bitslice(
    sbox_id: comptime_int,
    x0: u32,
    x1: u32,
    x2: u32,
    x3: u32,
    y0: *u32,
    y1: *u32,
    y2: *u32,
    y3: *u32,
) void {
    y0.* = 0;
    y1.* = 0;
    y2.* = 0;
    y3.* = 0;

    for (0..32) |i| {
        const bitPos: u5 = @intCast(i);

        var z = ((x0 >> bitPos) & 1) << 0 | ((x1 >> bitPos) & 1) << 1 | ((x2 >> bitPos) & 1) << 2 | ((x3 >> bitPos) & 1) << 3;

        z = SBOXES[sbox_id][z];

        if (((z >> 0) & 1) == 1)
            y0.* |= (@as(u32, 1) << bitPos)
        else
            y0.* &= ~(@as(u32, 1) << bitPos);

        if (((z >> 1) & 1) == 1)
            y1.* |= (@as(u32, 1) << bitPos)
        else
            y1.* &= ~(@as(u32, 1) << bitPos);

        if (((z >> 2) & 1) == 1)
            y2.* |= (@as(u32, 1) << bitPos)
        else
            y2.* &= ~(@as(u32, 1) << bitPos);

        if (((z >> 3) & 1) == 1)
            y3.* |= (@as(u32, 1) << bitPos)
        else
            y3.* &= ~(@as(u32, 1) << bitPos);
    }
}

fn rol(word: u32, by: comptime_int) u32 {
    return (word << by) | (word >> (32 - by));
}
