const std = @import("std");
const testing = std.testing;

const byte_operations = @import("../../utility/byte_operations.zig");
const word_to_bytes = byte_operations.word_to_bytes_be;
const bytes_to_word = byte_operations.bytes_to_word_be;

// ----------------------------------- PUBLIC CONSTANTS ----------------------------------- //

pub const BLOCK_SIZE = 128 / 8;

pub const KEY_SIZE_128 = 128 / 8;
pub const KEY_SIZE_192 = 192 / 8;
pub const KEY_SIZE_256 = 256 / 8;

// ----------------------------------- ENCRYPTION/DECRYPTION ----------------------------------- //

pub fn encrypt_block(
    n_rounds: comptime_int,
    block_in: *const [BLOCK_SIZE]u8,
    block_out: *[BLOCK_SIZE]u8,
    expanded_key: *const [4 * (n_rounds + 1)]u32,
) void {
    // Copy input buffer into state (we're treating the buffer as a column-first matrix).
    var state: [BLOCK_SIZE]u8 = undefined;
    @memcpy(state[0..], block_in);

    // Initial AddRoundKey.
    add_round_key(&state, expanded_key[0..4]);

    // Nr - 1 identical rounds.
    for (1..n_rounds) |round| {
        sub_bytes(&state);
        shift_rows(&state);
        mix_columns(&state);
        add_round_key(&state, @ptrCast(expanded_key[(4 * round)..(4 * round + 4)]));
    }

    // Last round is without MixColumns.
    sub_bytes(&state);
    shift_rows(&state);
    add_round_key(&state, @ptrCast(expanded_key[(4 * n_rounds)..(4 * n_rounds + 4)]));

    // Write the result into the destination buffer.
    @memcpy(block_out, &state);

    // Destroy the ciphertext in the internal buffer.
    @memset(state[0..], 0);
}

pub fn decrypt_block(
    n_rounds: comptime_int,
    block_in: *const [BLOCK_SIZE]u8,
    block_out: *[BLOCK_SIZE]u8,
    expanded_key: *const [4 * (n_rounds + 1)]u32,
) void {
    // Copy input buffer into state (we're treating the buffer as a column-first matrix).
    var state: [BLOCK_SIZE]u8 = undefined;
    @memcpy(state[0..], block_in);

    // Reverse the AddRoundKey that was applied after the last encryption round.
    add_round_key(&state, @ptrCast(expanded_key[(4 * n_rounds)..(4 * n_rounds + 4)]));

    // Nr - 1 identical rounds.
    for (1..n_rounds) |inv_round| {
        const round = n_rounds - inv_round;
        inv_shift_rows(&state);
        inv_sub_bytes(&state);
        add_round_key(&state, @ptrCast(expanded_key[(4 * round)..(4 * round + 4)]));
        inv_mix_columns(&state);
    }

    // Finish last round.
    inv_shift_rows(&state);
    inv_sub_bytes(&state);
    add_round_key(&state, expanded_key[0..4]);

    // Write the result into the destination buffer.
    @memcpy(block_out, &state);

    // Destroy the plaintext in the internal buffer.
    @memset(state[0..], 0);
}

pub fn aes128_encrypt_block(
    key: *const [KEY_SIZE_128]u8,
    block_in: *const [BLOCK_SIZE]u8,
    block_out: *[BLOCK_SIZE]u8,
) void {
    // Prepare the subkeys for AddRoundKey.
    var expanded_key = expand_key_128(key);
    defer @memset(&expanded_key, 0);

    // Call the generic encryption procedure.
    encrypt_block(N_ROUNDS_128, block_in, block_out, &expanded_key);
}

pub fn aes128_decrypt_block(
    key: *const [KEY_SIZE_128]u8,
    block_in: *const [BLOCK_SIZE]u8,
    block_out: *[BLOCK_SIZE]u8,
) void {
    // Prepare the subkeys for AddRoundKey.
    var expanded_key = expand_key_128(key);
    defer @memset(&expanded_key, 0);

    // Call the generic decryption procedure.
    decrypt_block(N_ROUNDS_128, block_in, block_out, &expanded_key);
}

pub fn aes192_encrypt_block(
    key: *const [KEY_SIZE_192]u8,
    block_in: *const [BLOCK_SIZE]u8,
    block_out: *[BLOCK_SIZE]u8,
) void {
    // Prepare the subkeys for AddRoundKey.
    var expanded_key = expand_key_192(key);
    defer @memset(&expanded_key, 0);

    // Call the generic encryption procedure.
    encrypt_block(N_ROUNDS_192, block_in, block_out, &expanded_key);
}

pub fn aes192_decrypt_block(
    key: *const [KEY_SIZE_192]u8,
    block_in: *const [BLOCK_SIZE]u8,
    block_out: *[BLOCK_SIZE]u8,
) void {
    // Prepare the subkeys for AddRoundKey.
    var expanded_key = expand_key_192(key);
    defer @memset(&expanded_key, 0);

    // Call the generic decryption procedure.
    decrypt_block(N_ROUNDS_192, block_in, block_out, &expanded_key);
}

pub fn aes256_encrypt_block(
    key: *const [KEY_SIZE_256]u8,
    block_in: *const [BLOCK_SIZE]u8,
    block_out: *[BLOCK_SIZE]u8,
) void {
    // Prepare the subkeys for AddRoundKey.
    var expanded_key = expand_key_256(key);
    defer @memset(&expanded_key, 0);

    // Call the generic encryption procedure.
    encrypt_block(N_ROUNDS_256, block_in, block_out, &expanded_key);
}

pub fn aes256_decrypt_block(
    key: *const [KEY_SIZE_256]u8,
    block_in: *const [BLOCK_SIZE]u8,
    block_out: *[BLOCK_SIZE]u8,
) void {
    // Prepare the subkeys for AddRoundKey.
    var expanded_key = expand_key_256(key);
    defer @memset(&expanded_key, 0);

    // Call the generic decryption procedure.
    decrypt_block(N_ROUNDS_256, block_in, block_out, &expanded_key);
}

// ----------------------------------- KEY EXPANSION ----------------------------------- //

pub fn expand_key(
    n_rounds: comptime_int,
    n_key_words: comptime_int,
    key: *const [n_key_words * 4]u8,
) [4 * (n_rounds + 1)]u32 {
    var expanded_key: [4 * (n_rounds + 1)]u32 = undefined;

    var i: u32 = 0;
    while (i <= n_key_words - 1) : (i += 1) {
        expanded_key[i] = bytes_to_word(&.{ key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3] });
    }
    while (i <= 4 * n_rounds + 3) : (i += 1) {
        var temp = expanded_key[i - 1];
        if (i % n_key_words == 0) {
            temp = sub_word(rot_word(temp)) ^ RCON[i / n_key_words - 1];
        } else if (n_key_words > 6 and i % n_key_words == 4) {
            temp = sub_word(temp);
        }
        expanded_key[i] = expanded_key[i - n_key_words] ^ temp;
    }

    return expanded_key;
}

pub fn expand_key_128(key: *const [KEY_SIZE_128]u8) [4 * (N_ROUNDS_128 + 1)]u32 {
    return expand_key(N_ROUNDS_128, KEY_SIZE_128 / 4, key);
}

pub fn expand_key_192(key: *const [KEY_SIZE_192]u8) [4 * (N_ROUNDS_192 + 1)]u32 {
    return expand_key(N_ROUNDS_192, KEY_SIZE_192 / 4, key);
}

pub fn expand_key_256(key: *const [KEY_SIZE_256]u8) [4 * (N_ROUNDS_256 + 1)]u32 {
    return expand_key(N_ROUNDS_256, KEY_SIZE_256 / 4, key);
}

// ----------------------------------- AES OPERATIONS ----------------------------------- //

pub fn add_round_key(state: *[BLOCK_SIZE]u8, subkey: *const [4]u32) void {
    for (0..4) |wi| {
        const subkey_bytes = word_to_bytes(subkey[wi]);
        for (0..4) |bi|
            state[wi * 4 + bi] ^= subkey_bytes[bi];
    }
}

pub fn sub_bytes(state: *[BLOCK_SIZE]u8) void {
    for (0..state.len) |i|
        state[i] = SBOX[state[i]];
}

pub fn shift_rows(state: *[BLOCK_SIZE]u8) void {
    var tmp: u8 = undefined;

    // Note: Since we store the state matrix as an array of columns,
    // we're technically shifting columns instead of rows.

    // Row 1 is shifted left by 1 position.
    tmp = state[0 * 4 + 1];
    state[0 * 4 + 1] = state[1 * 4 + 1];
    state[1 * 4 + 1] = state[2 * 4 + 1];
    state[2 * 4 + 1] = state[3 * 4 + 1];
    state[3 * 4 + 1] = tmp;

    // Row 2 is shifted left by 2 positions.
    tmp = state[0 * 4 + 2];
    state[0 * 4 + 2] = state[2 * 4 + 2];
    state[2 * 4 + 2] = tmp;
    tmp = state[1 * 4 + 2];
    state[1 * 4 + 2] = state[3 * 4 + 2];
    state[3 * 4 + 2] = tmp;

    // Row 3 is shifted left by 3 positions.
    tmp = state[0 * 4 + 3];
    state[0 * 4 + 3] = state[3 * 4 + 3];
    state[3 * 4 + 3] = state[2 * 4 + 3];
    state[2 * 4 + 3] = state[1 * 4 + 3];
    state[1 * 4 + 3] = tmp;
}

fn mix_one_column(column: *[4]u8) void {
    const c0 = column[0];
    const c1 = column[1];
    const c2 = column[2];
    const c3 = column[3];

    column[0] = xtime(c0) ^ (xtime(c1) ^ c1) ^ c2 ^ c3;
    column[1] = c0 ^ xtime(c1) ^ (xtime(c2) ^ c2) ^ c3;
    column[2] = c0 ^ c1 ^ xtime(c2) ^ (xtime(c3) ^ c3);
    column[3] = (xtime(c0) ^ c0) ^ c1 ^ c2 ^ xtime(c3);
}

pub fn mix_columns(state: *[BLOCK_SIZE]u8) void {
    for (0..4) |i|
        mix_one_column(@ptrCast(state[(4 * i)..(4 * i + 4)]));
}

pub fn inv_sub_bytes(state: *[BLOCK_SIZE]u8) void {
    for (0..state.len) |i|
        state[i] = INV_SBOX[state[i]];
}

pub fn inv_shift_rows(state: *[BLOCK_SIZE]u8) void {
    var tmp: u8 = undefined;

    // Note: Since we store the state matrix as an array of columns,
    // we're technically shifting columns instead of rows.

    // Row 1 is shifted right by 1 position.
    tmp = state[3 * 4 + 1];
    state[3 * 4 + 1] = state[2 * 4 + 1];
    state[2 * 4 + 1] = state[1 * 4 + 1];
    state[1 * 4 + 1] = state[0 * 4 + 1];
    state[0 * 4 + 1] = tmp;

    // Row 2 is shifted right by 2 positions.
    tmp = state[2 * 4 + 2];
    state[2 * 4 + 2] = state[0 * 4 + 2];
    state[0 * 4 + 2] = tmp;
    tmp = state[3 * 4 + 2];
    state[3 * 4 + 2] = state[1 * 4 + 2];
    state[1 * 4 + 2] = tmp;

    // Row 3 is shifted right by 3 positions.
    tmp = state[3 * 4 + 3];
    state[3 * 4 + 3] = state[0 * 4 + 3];
    state[0 * 4 + 3] = state[1 * 4 + 3];
    state[1 * 4 + 3] = state[2 * 4 + 3];
    state[2 * 4 + 3] = tmp;
}

fn inv_mix_one_column(column: *[4]u8) void {
    const c0 = column[0];
    const c1 = column[1];
    const c2 = column[2];
    const c3 = column[3];

    column[0] = gfmult(0x0e, c0) ^ gfmult(0x0b, c1) ^ gfmult(0x0d, c2) ^ gfmult(0x09, c3);
    column[1] = gfmult(0x09, c0) ^ gfmult(0x0e, c1) ^ gfmult(0x0b, c2) ^ gfmult(0x0d, c3);
    column[2] = gfmult(0x0d, c0) ^ gfmult(0x09, c1) ^ gfmult(0x0e, c2) ^ gfmult(0x0b, c3);
    column[3] = gfmult(0x0b, c0) ^ gfmult(0x0d, c1) ^ gfmult(0x09, c2) ^ gfmult(0x0e, c3);
}

pub fn inv_mix_columns(state: *[BLOCK_SIZE]u8) void {
    for (0..4) |i|
        inv_mix_one_column(@ptrCast(state[(4 * i)..(4 * i + 4)]));
}

fn sub_word(word: u32) u32 {
    var bytes = word_to_bytes(word);
    for (0..4) |i|
        bytes[i] = SBOX[bytes[i]];
    return bytes_to_word(&bytes);
}

fn rot_word(word: u32) u32 {
    const bytes = word_to_bytes(word);
    return bytes_to_word(&.{ bytes[1], bytes[2], bytes[3], bytes[0] });
}

// ----------------------------------- GALOIS FIELD HELPERS ----------------------------------- //

fn xtime(element: u8) u8 {
    return if (element & 0x80 != 0)
        // reduction modulo the AES irreducible polynomial
        ((element << 1) ^ 0x1b)
    else
        (element << 1);
}

fn gfmult(factor: comptime_int, element: u8) u8 {
    const xe = xtime(element);
    const x2e = xtime(xe);
    const x3e = xtime(x2e);

    return if (factor == 0x09)
        // 0x09 = 0x08 ^ 0x01
        x3e ^ element
    else if (factor == 0x0b)
        // 0x0b = 0x08 ^ 0x03
        x3e ^ xe ^ element
    else if (factor == 0x0d)
        // 0x0d = 0x08 ^ 0x05
        x3e ^ x2e ^ element
    else if (factor == 0x0e)
        // 0x0e = 0x08 ^ 0x06
        x3e ^ x2e ^ xe
    else
        unreachable;
}

// ----------------------------------- CRYPTOGRAPHIC CONSTANTS ----------------------------------- //

pub const N_ROUNDS_128 = 10;
pub const N_ROUNDS_192 = 12;
pub const N_ROUNDS_256 = 14;

pub const SBOX = [_]u8{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

pub const INV_SBOX = [_]u8{
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};

pub const RCON = [_]u32{
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000,
};
