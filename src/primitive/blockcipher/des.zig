const std = @import("std");
const testing = std.testing;

// ----------------------------------- DES CONSTANTS -----------------------------------  //

pub const DES_BLOCK_SIZE = 64 / 8;

pub const DES_TRUE_KEY_SIZE = 56 / 8;
pub const DES_ENCODED_KEY_SIZE = 64 / 8;

pub const DES_SUBKEY_SIZE = 48 / 8;

pub const DES_N_ROUNDS = 16;

pub const DES_INITIAL_PERMUTATION = [_]u6{
    58, 50, 42, 35, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
};

pub const DES_INV_INITIAL_PERMUTATION = [_]u6{
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9,  49, 17, 57, 25,
};

pub const DES_BIT_SELECTION_TABLE_E = [_]u5{
    32, 1,  2,  3,  4,  5,
    4,  5,  6,  7,  8,  9,
    8,  9,  10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
};

pub const DES_KS_SHIFT_SCHEDULE = .{ 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

// ----------------------------------- ENCRYPTION/DECRYPTION -----------------------------------  //

pub fn des_encrypt_block(
    block_in: *const [DES_BLOCK_SIZE]u8,
    block_out: *[DES_BLOCK_SIZE]u8,
    key: *const [DES_ENCODED_KEY_SIZE]u8,
) void {
    var state: [DES_BLOCK_SIZE]u8 = undefined;
    des_initial_permutation(block_in, &state);

    var expanded_key = des_expand_key(key);
    defer @memset(&expanded_key, 0);

    for (0..DES_N_ROUNDS) |round|
        des_perform_round(&state, expanded_key[round]);

    des_inv_initial_permutation(&state, block_out);
}

pub fn des_decrypt_block(
    block_in: *const [DES_BLOCK_SIZE]u8,
    block_out: *[DES_BLOCK_SIZE]u8,
    key: *const [DES_ENCODED_KEY_SIZE]u8,
) void {
    var state: [DES_BLOCK_SIZE]u8 = undefined;
    des_inv_initial_permutation(block_in, &state);

    var expanded_key = des_expand_key(key);
    defer @memset(&expanded_key, 0);

    for (0..DES_N_ROUNDS) |round|
        des_perform_round(&state, expanded_key[DES_N_ROUNDS - round - 1]);

    des_initial_permutation(&state, block_out);
}

pub fn des_expand_key(key: *const [DES_ENCODED_KEY_SIZE]u8) [DES_N_ROUNDS][DES_SUBKEY_SIZE]u8 {
    var cd = des_permuted_choice_1(key);
    var subkeys: [DES_N_ROUNDS][DES_SUBKEY_SIZE]u8 = undefined;

    for (0..DES_N_ROUNDS) |i| {
        rol(cd[0 .. DES_TRUE_KEY_SIZE / 2], DES_KS_SHIFT_SCHEDULE[i]);
        rol(cd[DES_TRUE_KEY_SIZE / 2 ..], DES_KS_SHIFT_SCHEDULE[i]);
        des_permuted_choice_2(cd, &subkeys[i]);
    }
}

pub fn des_permuted_choice_1(key: *const [DES_ENCODED_KEY_SIZE]u8) [DES_TRUE_KEY_SIZE]u8 {
    const PC1 = .{
        57, 49, 41, 33, 25, 17, 9,  1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
    };

    var result: [DES_TRUE_KEY_SIZE]u8 = undefined;
    permute_bits(DES_TRUE_KEY_SIZE, key, &result, PC1);

    return result;
}

pub fn des_permuted_choice_2(cd: *const [DES_TRUE_KEY_SIZE]u8, out: *[DES_SUBKEY_SIZE]u8) void {
    const PC2 = .{
        14, 17, 11, 24, 1,  5,  3,  28, 15, 6,  21, 10, 23, 19, 12, 4,  26, 8,  16, 7,  27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
    };

    permute_bits(DES_SUBKEY_SIZE, cd, out, PC2);
}

pub fn des_perform_round(state: *[DES_BLOCK_SIZE]u8, subkey: *[DES_SUBKEY_SIZE]u8) void {
    const f_output = des_cipher_function_f(state[DES_BLOCK_SIZE / 2 ..], subkey);
    const new_r = xor(DES_BLOCK_SIZE / 2, state[0 .. DES_BLOCK_SIZE / 2], f_output);

    @memcpy(state[0 .. DES_BLOCK_SIZE / 2], state[DES_BLOCK_SIZE / 2 ..]);
    @memcpy(state[DES_BLOCK_SIZE / 2 ..], new_r[0..]);
}

pub fn des_cipher_function_f(word: [DES_BLOCK_SIZE / 2]u8, subkey: [DES_SUBKEY_SIZE]u8) [DES_BLOCK_SIZE / 2]u8 {
    // todo
    _ = .{ word, subkey };
}

pub fn des_initial_permutation(in: *const [DES_BLOCK_SIZE]u8, out: *[DES_BLOCK_SIZE]u8) void {
    permute_bits(DES_BLOCK_SIZE, in, out, DES_INITIAL_PERMUTATION);
}

pub fn des_inv_initial_permutation(in: *const [DES_BLOCK_SIZE]u8, out: *[DES_BLOCK_SIZE]u8) void {
    permute_bits(DES_BLOCK_SIZE, in, out, DES_INV_INITIAL_PERMUTATION);
}

// ----------------------------------- HELPERS -----------------------------------  //

fn permute_bits(L: comptime_int, in: *const [8]u8, out: *[L]u8, key: [8 * L]u6) void {
    for (0..8 * L) |i| {
        const pi = key[i];
        const bit = get_nth_bit(in, pi);
        set_nth_bit(out, pi, bit);
    }
}

fn get_nth_bit(bytes: *const [8]u8, n: u6) u1 {
    const byte_idx = n / 8;
    const bit_idx = n % 8;

    return @truncate(bytes[byte_idx] >> (7 - bit_idx));
}

fn set_nth_bit(bytes: *const [8]u8, n: u6, bit: u1) void {
    const byte_idx = n / 8;
    const bit_idx = n % 8;

    if (bit == 1)
        bytes[byte_idx] |= (1 << (7 - bit_idx))
    else
        bytes[byte_idx] &= ~(1 << (7 - bit_idx));
}

fn xor(L: comptime_int, a: [L]u8, b: [L]u8) [L]u8 {
    var result: [L]u8 = undefined;
    for (0..L) |i|
        result[i] = a[i] ^ b[i];
    return result;
}

fn rol(word: *[DES_TRUE_KEY_SIZE / 2]u8, positions: comptime_int) void {
    // todo
    _ = .{ word, positions };
}

// ----------------------------------- TEST VECTORS -----------------------------------  //

//
