const std = @import("std");
const testing = std.testing;

const CryptoError = error{
    InvalidPadding,
};

pub fn pkcs5_pad(block: *[8]u8, plaintext_length: usize) void {
    return pkcs7_pad(8, block, plaintext_length);
}

pub fn pkcs5_unpad(block: *[8]u8) !u8 {
    return pkcs7_unpad(8, block);
}

pub fn pkcs7_pad(
    comptime block_size: u8,
    block: *[block_size]u8,
    plaintext_length: usize,
) void {
    const plaintext_block_residue_length: u8 = plaintext_length % block_size;
    const padding_val: u8 = block_size - plaintext_block_residue_length;
    @memset(block[plaintext_block_residue_length..], padding_val);
}

pub fn pkcs7_unpad(
    comptime block_size: u8,
    block: *const [block_size]u8,
) !u8 {
    const padding_val = block[block_size - 1];
    if (padding_val == 0 or padding_val > block_size)
        return CryptoError.InvalidPadding;

    const plaintext_residue_length = block_size - padding_val;

    for (plaintext_residue_length..block_size) |i|
        if (block[i] != padding_val)
            return CryptoError.InvalidPadding;

    return plaintext_residue_length;
}

test "PKCS #7 padding" {
    // TODO
}

test "PKCS #7 unpadding" {
    // TODO
}
