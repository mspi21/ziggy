const std = @import("std");
const testing = std.testing;

// ----------------------------------- DES CONSTANTS -----------------------------------  //

pub const DES_BLOCK_SIZE = 64 / 8;
pub const DES_TRUE_KEY_SIZE = 56 / 8;
pub const DES_ENCODED_KEY_SIZE = 64 / 8;
pub const DES_N_ROUNDS = 16;
pub const DES_SUBKEY_SIZE = 48 / 8;

const DES_INITIAL_PERMUTATION = [_]u6{
    58 - 1, 50 - 1, 42 - 1, 35 - 1, 26 - 1, 18 - 1, 10 - 1, 2 - 1,
    60 - 1, 52 - 1, 44 - 1, 36 - 1, 28 - 1, 20 - 1, 12 - 1, 4 - 1,
    62 - 1, 54 - 1, 46 - 1, 38 - 1, 30 - 1, 22 - 1, 14 - 1, 6 - 1,
    64 - 1, 56 - 1, 48 - 1, 40 - 1, 32 - 1, 24 - 1, 16 - 1, 8 - 1,
    57 - 1, 49 - 1, 41 - 1, 33 - 1, 25 - 1, 17 - 1, 9 - 1,  1 - 1,
    59 - 1, 51 - 1, 43 - 1, 35 - 1, 27 - 1, 19 - 1, 11 - 1, 3 - 1,
    61 - 1, 53 - 1, 45 - 1, 37 - 1, 29 - 1, 21 - 1, 13 - 1, 5 - 1,
    63 - 1, 55 - 1, 47 - 1, 39 - 1, 31 - 1, 23 - 1, 15 - 1, 7 - 1,
};

const DES_INV_INITIAL_PERMUTATION = [_]u6{
    40 - 1, 8 - 1, 48 - 1, 16 - 1, 56 - 1, 24 - 1, 64 - 1, 32 - 1,
    39 - 1, 7 - 1, 47 - 1, 15 - 1, 55 - 1, 23 - 1, 63 - 1, 31 - 1,
    38 - 1, 6 - 1, 46 - 1, 14 - 1, 54 - 1, 22 - 1, 62 - 1, 30 - 1,
    37 - 1, 5 - 1, 45 - 1, 13 - 1, 53 - 1, 21 - 1, 61 - 1, 29 - 1,
    36 - 1, 4 - 1, 44 - 1, 12 - 1, 52 - 1, 20 - 1, 60 - 1, 28 - 1,
    35 - 1, 3 - 1, 43 - 1, 11 - 1, 51 - 1, 19 - 1, 59 - 1, 27 - 1,
    34 - 1, 2 - 1, 42 - 1, 10 - 1, 50 - 1, 18 - 1, 58 - 1, 26 - 1,
    33 - 1, 1 - 1, 41 - 1, 9 - 1,  49 - 1, 17 - 1, 57 - 1, 25 - 1,
};

const DES_BIT_SELECTION_TABLE_E = [_]u6{
    32 - 1, 1 - 1,  2 - 1,  3 - 1,  4 - 1,  5 - 1,
    4 - 1,  5 - 1,  6 - 1,  7 - 1,  8 - 1,  9 - 1,
    8 - 1,  9 - 1,  10 - 1, 11 - 1, 12 - 1, 13 - 1,
    12 - 1, 13 - 1, 14 - 1, 15 - 1, 16 - 1, 17 - 1,
    16 - 1, 17 - 1, 18 - 1, 19 - 1, 20 - 1, 21 - 1,
    20 - 1, 21 - 1, 22 - 1, 23 - 1, 24 - 1, 25 - 1,
    24 - 1, 25 - 1, 26 - 1, 27 - 1, 28 - 1, 29 - 1,
    28 - 1, 29 - 1, 30 - 1, 31 - 1, 32 - 1, 1 - 1,
};

const DES_S_BOXES = [8][64]u4{
    .{ 14, 0, 4, 15, 13, 7, 1, 4, 2, 14, 15, 2, 11, 13, 8, 1, 3, 10, 10, 6, 6, 12, 12, 11, 5, 9, 9, 5, 0, 3, 7, 8, 4, 15, 1, 12, 14, 8, 8, 2, 13, 4, 6, 9, 2, 1, 11, 7, 15, 5, 12, 11, 9, 3, 7, 14, 3, 10, 10, 0, 5, 6, 0, 13 },
    .{ 15, 3, 1, 13, 8, 4, 14, 7, 6, 15, 11, 2, 3, 8, 4, 14, 9, 12, 7, 0, 2, 1, 13, 10, 12, 6, 0, 9, 5, 11, 10, 5, 0, 13, 14, 8, 7, 10, 11, 1, 10, 3, 4, 15, 13, 4, 1, 2, 5, 11, 8, 6, 12, 7, 6, 12, 9, 0, 3, 5, 2, 14, 15, 9 },
    .{ 10, 13, 0, 7, 9, 0, 14, 9, 6, 3, 3, 4, 15, 6, 5, 10, 1, 2, 13, 8, 12, 5, 7, 14, 11, 12, 4, 11, 2, 15, 8, 1, 13, 1, 6, 10, 4, 13, 9, 0, 8, 6, 15, 9, 3, 8, 0, 7, 11, 4, 1, 15, 2, 14, 12, 3, 5, 11, 10, 5, 14, 2, 7, 12 },
    .{ 7, 13, 13, 8, 14, 11, 3, 5, 0, 6, 6, 15, 9, 0, 10, 3, 1, 4, 2, 7, 8, 2, 5, 12, 11, 1, 12, 10, 4, 14, 15, 9, 10, 3, 6, 15, 9, 0, 0, 6, 12, 10, 11, 1, 7, 13, 13, 8, 15, 9, 1, 4, 3, 5, 14, 11, 5, 12, 2, 7, 8, 2, 4, 14 },
    .{ 2, 14, 12, 11, 4, 2, 1, 12, 7, 4, 10, 7, 11, 13, 6, 1, 8, 5, 5, 0, 3, 15, 15, 10, 13, 3, 0, 9, 14, 8, 9, 6, 4, 11, 2, 8, 1, 12, 11, 7, 10, 1, 13, 14, 7, 2, 8, 13, 15, 6, 9, 15, 12, 0, 5, 9, 6, 10, 3, 4, 0, 5, 14, 3 },
    .{ 12, 10, 1, 15, 10, 4, 15, 2, 9, 7, 2, 12, 6, 9, 8, 5, 0, 6, 13, 1, 3, 13, 4, 14, 14, 0, 7, 11, 5, 3, 11, 8, 9, 4, 14, 3, 15, 2, 5, 12, 2, 9, 8, 5, 12, 15, 3, 10, 7, 11, 0, 14, 4, 1, 10, 7, 1, 6, 13, 0, 11, 8, 6, 13 },
    .{ 4, 13, 11, 0, 2, 11, 14, 7, 15, 4, 0, 9, 8, 1, 13, 10, 3, 14, 12, 3, 9, 5, 7, 12, 5, 2, 10, 15, 6, 8, 1, 6, 1, 6, 4, 11, 11, 13, 13, 8, 12, 1, 3, 4, 7, 10, 14, 7, 10, 9, 15, 5, 6, 0, 8, 15, 0, 14, 5, 2, 9, 3, 2, 12 },
    .{ 13, 1, 2, 15, 8, 13, 4, 8, 6, 10, 15, 3, 11, 7, 1, 4, 10, 12, 9, 5, 3, 6, 14, 11, 5, 0, 0, 14, 12, 9, 7, 2, 7, 2, 11, 1, 4, 14, 1, 7, 9, 4, 12, 10, 14, 8, 2, 13, 0, 15, 6, 12, 10, 9, 13, 0, 15, 3, 3, 5, 5, 6, 8, 11 },
};

const DES_PERMUTATION_FUNCTION_P = [_]u6{
    16 - 1, 7 - 1,  20 - 1, 21 - 1, 29 - 1, 12 - 1, 28 - 1, 17 - 1,
    1 - 1,  15 - 1, 23 - 1, 26 - 1, 5 - 1,  18 - 1, 31 - 1, 10 - 1,
    2 - 1,  8 - 1,  24 - 1, 14 - 1, 32 - 1, 27 - 1, 3 - 1,  9 - 1,
    19 - 1, 13 - 1, 30 - 1, 6 - 1,  22 - 1, 11 - 1, 4 - 1,  25 - 1,
};

const DES_KS_SHIFT_SCHEDULE = .{ 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

// ----------------------------------- ENCRYPTION/DECRYPTION -----------------------------------  //

pub fn des_encrypt_block(
    key: *const [DES_ENCODED_KEY_SIZE]u8,
    block_in: *const [DES_BLOCK_SIZE]u8,
    block_out: *[DES_BLOCK_SIZE]u8,
) void {
    var state: [DES_BLOCK_SIZE]u8 = undefined;
    des_initial_permutation(block_in, &state);

    var expanded_key = des_expand_key(key);
    defer @memset(&expanded_key, .{ 0, 0, 0, 0, 0, 0 });

    for (0..DES_N_ROUNDS) |round|
        des_perform_round(&state, &expanded_key[round]);

    des_inv_initial_permutation(&state, block_out);
}

pub fn des_decrypt_block(
    key: *const [DES_ENCODED_KEY_SIZE]u8,
    block_in: *const [DES_BLOCK_SIZE]u8,
    block_out: *[DES_BLOCK_SIZE]u8,
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
    const cd = des_permuted_choice_1(key);

    // Probably the least stupid software implementation that I could think of.
    var c_i: u28 = @truncate(std.mem.readInt(u56, &cd, .big) >> 28);
    var d_i: u28 = @truncate(std.mem.readInt(u56, &cd, .big));

    var subkeys: [DES_N_ROUNDS][DES_SUBKEY_SIZE]u8 = undefined;

    inline for (0..DES_N_ROUNDS) |i| {
        c_i = rotate_left(c_i, DES_KS_SHIFT_SCHEDULE[i]);
        d_i = rotate_left(d_i, DES_KS_SHIFT_SCHEDULE[i]);
        des_permuted_choice_2(c_i, d_i, &subkeys[i]);
    }

    return subkeys;
}

pub fn des_permuted_choice_1(key: *const [DES_ENCODED_KEY_SIZE]u8) [DES_TRUE_KEY_SIZE]u8 {
    const PC1 = .{
        57 - 1, 49 - 1, 41 - 1, 33 - 1, 25 - 1, 17 - 1, 9 - 1,  1 - 1,  58 - 1, 50 - 1, 42 - 1, 34 - 1, 26 - 1, 18 - 1,
        10 - 1, 2 - 1,  59 - 1, 51 - 1, 43 - 1, 35 - 1, 27 - 1, 19 - 1, 11 - 1, 3 - 1,  60 - 1, 52 - 1, 44 - 1, 36 - 1,
        63 - 1, 55 - 1, 47 - 1, 39 - 1, 31 - 1, 23 - 1, 15 - 1, 7 - 1,  62 - 1, 54 - 1, 46 - 1, 38 - 1, 30 - 1, 22 - 1,
        14 - 1, 6 - 1,  61 - 1, 53 - 1, 45 - 1, 37 - 1, 29 - 1, 21 - 1, 13 - 1, 5 - 1,  28 - 1, 20 - 1, 12 - 1, 4 - 1,
    };

    var result: [DES_TRUE_KEY_SIZE]u8 = undefined;
    permute_bits(DES_TRUE_KEY_SIZE, key, &result, &PC1);

    return result;
}

pub fn des_permuted_choice_2(c: u28, d: u28, out: *[DES_SUBKEY_SIZE]u8) void {
    const PC2 = .{
        14 - 1, 17 - 1, 11 - 1, 24 - 1, 1 - 1,  5 - 1,  3 - 1,  28 - 1, 15 - 1, 6 - 1,  21 - 1, 10 - 1,
        23 - 1, 19 - 1, 12 - 1, 4 - 1,  26 - 1, 8 - 1,  16 - 1, 7 - 1,  27 - 1, 20 - 1, 13 - 1, 2 - 1,
        41 - 1, 52 - 1, 31 - 1, 37 - 1, 47 - 1, 55 - 1, 30 - 1, 40 - 1, 51 - 1, 45 - 1, 33 - 1, 48 - 1,
        44 - 1, 49 - 1, 39 - 1, 56 - 1, 34 - 1, 53 - 1, 46 - 1, 42 - 1, 50 - 1, 36 - 1, 29 - 1, 32 - 1,
    };

    const cd = @as(u56, c) << 28 | @as(u56, d);
    var cd_bytes: [DES_TRUE_KEY_SIZE]u8 = undefined;
    std.mem.writeInt(u56, &cd_bytes, cd, .big);

    permute_bits(DES_SUBKEY_SIZE, &cd_bytes, out, &PC2);
}

pub fn des_perform_round(state: *[DES_BLOCK_SIZE]u8, subkey: *[DES_SUBKEY_SIZE]u8) void {
    var f_output = des_cipher_function_f(state[DES_BLOCK_SIZE / 2 ..], subkey);
    const new_r = xor(DES_BLOCK_SIZE / 2, state[0 .. DES_BLOCK_SIZE / 2], &f_output);

    @memcpy(state[0 .. DES_BLOCK_SIZE / 2], state[DES_BLOCK_SIZE / 2 ..]);
    @memcpy(state[DES_BLOCK_SIZE / 2 ..], new_r[0..]);
}

pub fn des_cipher_function_f(word: *const [DES_BLOCK_SIZE / 2]u8, subkey: *const [DES_SUBKEY_SIZE]u8) [DES_BLOCK_SIZE / 2]u8 {
    // The input word is expanded to 48 bits.
    var expanded_word: [DES_SUBKEY_SIZE]u8 = undefined;
    permute_bits(DES_SUBKEY_SIZE, word, &expanded_word, &DES_BIT_SELECTION_TABLE_E);

    for (0..DES_SUBKEY_SIZE) |i|
        expanded_word[i] ^= subkey[i];

    var sbox_output = std.mem.zeroes([DES_BLOCK_SIZE / 2]u8);

    inline for (0..8) |i| {
        var sbox_input: u6 = @as(u6, get_nth_bit(DES_SUBKEY_SIZE, &expanded_word, i * 6));
        inline for (1..6) |j| {
            sbox_input <<= 1;
            sbox_input |= @as(u6, get_nth_bit(DES_SUBKEY_SIZE, &expanded_word, i * 6 + j));
        }
        sbox_output[i / 2] |= @as(u8, DES_S_BOXES[i][sbox_input]) << if (i % 2 == 0) 4 else 0;
    }

    var expansion_output: [DES_BLOCK_SIZE / 2]u8 = undefined;
    permute_bits(DES_BLOCK_SIZE / 2, &sbox_output, &expansion_output, &DES_PERMUTATION_FUNCTION_P);

    return expansion_output;
}

pub fn des_initial_permutation(in: *const [DES_BLOCK_SIZE]u8, out: *[DES_BLOCK_SIZE]u8) void {
    permute_bits(DES_BLOCK_SIZE, in[0..], out, &DES_INITIAL_PERMUTATION);
}

pub fn des_inv_initial_permutation(in: *const [DES_BLOCK_SIZE]u8, out: *[DES_BLOCK_SIZE]u8) void {
    permute_bits(DES_BLOCK_SIZE, in[0..], out, &DES_INV_INITIAL_PERMUTATION);
}

// ----------------------------------- HELPERS -----------------------------------  //

fn permute_bits(L: comptime_int, in: []const u8, out: *[L]u8, key: *const [8 * L]u6) void {
    for (0..8 * L) |i| {
        const pi = key[i];
        if (pi >= in.len * 8)
            @panic("Bit index out of range!");
        const bit = get_nth_bit(8, in, pi);
        set_nth_bit(L, out, @intCast(i), bit);
    }
}

fn get_nth_bit(comptime L: u4, bytes: []const u8, n: u6) u1 {
    if (L > 8 or n >= bytes.len * 8)
        @panic("Bit index out of range!");

    const byte_idx = n / 8;
    const bit_idx = n % 8;

    return @truncate(bytes[byte_idx] >> @intCast(7 - bit_idx));
}

fn set_nth_bit(comptime L: u4, bytes: []u8, n: u6, bit: u1) void {
    if (L > 8 or n >= bytes.len * 8)
        @panic("Bit index out of range!");

    const byte_idx = n / 8;
    const bit_idx = n % 8;

    if (bit == 1)
        bytes[byte_idx] |= (@as(u8, 1) << @intCast(7 - bit_idx))
    else
        bytes[byte_idx] &= ~(@as(u8, 1) << @intCast(7 - bit_idx));
}

fn xor(L: comptime_int, a: *const [L]u8, b: *const [L]u8) [L]u8 {
    var result: [L]u8 = undefined;
    for (0..L) |i|
        result[i] = a[i] ^ b[i];
    return result;
}

fn rotate_left(x: u28, positions: comptime_int) u28 {
    return x << positions | x >> (28 - positions);
}
