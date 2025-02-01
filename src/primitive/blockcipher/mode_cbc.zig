const std = @import("std");
const testing = std.testing;

const padding = @import("padding.zig");

const CryptoError = error{
    PlaintextExceedsBlockSize,
    BufferSizeMismatch,
};

pub fn cipher_fn_t(comptime block_size: u8, comptime key_size: usize) type {
    return fn (
        key: *const [key_size]u8,
        block_in: *const [block_size]u8,
        block_out: *[block_size]u8,
    ) void;
}

pub fn CbcPkcs7Ctx(
    comptime block_size: u8,
    comptime key_size: usize,
    cipher_fn: cipher_fn_t(block_size, key_size),
    comptime decrypt: bool,
) type {
    return struct {
        const BLOCK_SIZE = block_size;
        const KEY_SIZE = key_size;
        const CIPHER_FN = cipher_fn;
        const DECRYPT = decrypt;

        iv: [block_size]u8,
        key: [key_size]u8,
    };
}

pub fn get_padded_length(comptime block_size: u8, plaintext_length: usize) usize {
    return (plaintext_length / block_size + 1) * block_size;
}

pub fn get_padded_buffer_length(comptime block_size: u8, plaintext: []const u8) usize {
    return get_padded_length(block_size, plaintext.len);
}

pub fn cbc_pkcs7_encrypt_new(
    comptime block_size: u8,
    comptime key_size: usize,
    cipher_fn: cipher_fn_t(block_size, key_size),
    key: *const [key_size]u8,
    iv: *const [block_size]u8,
) CbcPkcs7Ctx(block_size, key_size, cipher_fn, false) {
    return CbcPkcs7Ctx(block_size, key_size, cipher_fn, false){
        .iv = iv.*,
        .key = key.*,
    };
}

pub fn cbc_pkcs7_encrypt_block(
    comptime block_size: u8,
    comptime key_size: usize,
    cipher_fn: cipher_fn_t(block_size, key_size),
    ctx: *CbcPkcs7Ctx(block_size, key_size, cipher_fn, false),
    plaintext: *const [block_size]u8,
    ciphertext: *[block_size]u8,
) void {
    var tmp: [block_size]u8 = plaintext.*;
    defer @memset(&tmp, 0);

    xor(block_size, tmp[0..], ctx.iv[0..], tmp[0..]);
    cipher_fn(&ctx.key, &tmp, &tmp);

    @memcpy(ctx.iv[0..], tmp[0..]);
    @memcpy(ciphertext[0..], tmp[0..]);
}

pub fn cbc_pkcs7_encrypt_final(
    comptime block_size: u8,
    comptime key_size: usize,
    cipher_fn: cipher_fn_t(block_size, key_size),
    ctx: *CbcPkcs7Ctx(block_size, key_size, cipher_fn, false),
    plaintext: []const u8,
    ciphertext: *[block_size]u8,
) !void {
    if (plaintext.len >= block_size)
        return CryptoError.PlaintextExceedsBlockSize;

    var last_block: [block_size]u8 = undefined;
    @memcpy(last_block[0..plaintext.len], plaintext[0..]);
    defer @memset(&last_block, 0);

    padding.pkcs7_pad(block_size, &last_block, plaintext.len);
    return cbc_pkcs7_encrypt_block(block_size, key_size, cipher_fn, ctx, &last_block, ciphertext);
}

pub fn cbc_pkcs7_encrypt_destroy(
    comptime block_size: u8,
    comptime key_size: usize,
    cipher_fn: cipher_fn_t(block_size, key_size),
    ctx: *CbcPkcs7Ctx(block_size, key_size, cipher_fn, false),
) void {
    const ctx_size = @sizeOf(@TypeOf(ctx.*));
    const CtxByteSlice = *[ctx_size]u8;

    @memset(@as(CtxByteSlice, @ptrCast(ctx)), 0);
}

pub fn cbc_pkcs7_decrypt_new(
    comptime block_size: u8,
    comptime key_size: usize,
    cipher_fn: cipher_fn_t(block_size, key_size),
    key: *const [key_size]u8,
    iv: *const [block_size]u8,
) CbcPkcs7Ctx(block_size, key_size, cipher_fn, true) {
    return CbcPkcs7Ctx(block_size, key_size, cipher_fn, true){
        .iv = iv.*,
        .key = key.*,
    };
}

pub fn cbc_pkcs7_decrypt_block(
    comptime block_size: u8,
    comptime key_size: usize,
    cipher_fn: cipher_fn_t(block_size, key_size),
    ctx: *CbcPkcs7Ctx(block_size, key_size, cipher_fn, true),
    ciphertext: *const [block_size]u8,
    plaintext: *[block_size]u8,
) void {
    var tmp: [block_size]u8 = undefined;
    defer @memset(&tmp, 0);

    cipher_fn(&ctx.key, ciphertext, &tmp);
    xor(block_size, tmp[0..], ctx.iv[0..], tmp[0..]);

    @memcpy(ctx.iv[0..], ciphertext[0..]);
    @memcpy(plaintext[0..], tmp[0..]);
}

pub fn cbc_pkcs7_decrypt_final(
    comptime block_size: u8,
    comptime key_size: usize,
    cipher_fn: cipher_fn_t(block_size, key_size),
    ctx: *CbcPkcs7Ctx(block_size, key_size, cipher_fn, true),
    ciphertext: []const u8,
    plaintext: []u8,
) !u8 {
    if (ciphertext.len != block_size or plaintext.len != block_size)
        return CryptoError.BufferSizeMismatch;

    cbc_pkcs7_decrypt_block(block_size, key_size, cipher_fn, ctx, @ptrCast(ciphertext), @ptrCast(plaintext));
    return padding.pkcs7_unpad(block_size, @ptrCast(plaintext));
}

pub fn cbc_pkcs7_decrypt_destroy(
    comptime block_size: u8,
    comptime key_size: usize,
    cipher_fn: cipher_fn_t(block_size, key_size),
    ctx: *CbcPkcs7Ctx(block_size, key_size, cipher_fn, true),
) void {
    const ctx_size = @sizeOf(@TypeOf(ctx.*));
    const CtxByteSlice = *[ctx_size]u8;

    @memset(@as(CtxByteSlice, @ptrCast(ctx)), 0);
}

fn xor(comptime block_size: u8, x: *const [block_size]u8, y: *const [block_size]u8, out: *[block_size]u8) void {
    for (0..block_size) |i|
        out[i] = x[i] ^ y[i];
}
