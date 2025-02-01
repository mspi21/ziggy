const std = @import("std");
const testing = std.testing;

const CryptoError = error{
    MessageLengthLimitExceeded,
    BufferSizeMismatch,
    InvalidIVLength,
    InvalidTagLength,
    IncorrectAuthenticationTag,
};

pub const GCM_128_BLOCK_SIZE = 128 / 8;

pub fn gcm_128_cipher_fn_t(comptime key_size: usize) type {
    return fn (
        key: *const [key_size]u8,
        block_in: *const [GCM_128_BLOCK_SIZE]u8,
        block_out: *[GCM_128_BLOCK_SIZE]u8,
    ) void;
}

fn Gcm128Ctx(
    comptime cipher_key_size: usize,
    cipher_encrypt_fn: gcm_128_cipher_fn_t(cipher_key_size),
) type {
    return struct {
        const BLOCK_SIZE = GCM_128_BLOCK_SIZE;
        const AAD_MAX_BYTES = (1 << 64) / 8;
        const TEXT_MAX_BYTES = ((1 << 39) - 256) / 8;
        const TAG_MAX_BYTES = 128 / 8;

        const KEY_SIZE = cipher_key_size;
        const CIPHER_FN = cipher_encrypt_fn;

        key: [cipher_key_size]u8,
        keystream: [BLOCK_SIZE]u8,
        counter: [BLOCK_SIZE]u8,
        ghash_x: [BLOCK_SIZE]u8,
        h: [BLOCK_SIZE]u8,
        ciphertext_buffer: [BLOCK_SIZE]u8,
        ciphertext_length: u64,
        aad_length: u64,
    };
}

pub fn gcm_128_new(
    comptime cipher_key_size: usize,
    cipher_encrypt_fn: gcm_128_cipher_fn_t(cipher_key_size),
    key: *const [cipher_key_size]u8,
    iv: []const u8,
) !Gcm128Ctx(cipher_key_size, cipher_encrypt_fn) {
    if (iv.len == 0) {
        return CryptoError.InvalidIVLength;
    }

    var ctx = Gcm128Ctx(cipher_key_size, cipher_encrypt_fn){
        .key = undefined,
        .keystream = undefined,
        .counter = undefined,
        .ghash_x = undefined,
        .h = undefined,
        .ciphertext_buffer = undefined,
        .ciphertext_length = 0,
        .aad_length = 0,
    };

    // Set the encryption/decryption key.
    @memcpy(&ctx.key, key);

    // Compute the `H` value.
    cipher_encrypt_fn(&ctx.key, &std.mem.zeroes([GCM_128_BLOCK_SIZE]u8), &ctx.h);

    // Set the counter initial value (`Y_0`).
    if (iv.len == 96 / 8) {
        @memcpy(ctx.counter[0 .. 96 / 8], iv);
        @memset(ctx.counter[(96 / 8)..(ctx.counter.len - 1)], 0x00);
        ctx.counter[ctx.counter.len - 1] = 0x01;
    } else {
        gcm_128_ghash(&ctx.h, &.{}, iv, &ctx.counter);
    }

    return ctx;
}

pub fn gcm_128_destroy(
    comptime cipher_key_size: usize,
    cipher_encrypt_fn: gcm_128_cipher_fn_t(cipher_key_size),
    ctx: *Gcm128Ctx(cipher_key_size, cipher_encrypt_fn),
) void {
    @memset(&ctx, 0);
}

// Important: this function must only be called at most once
// AFTER the context is initialized but BEFORE any data is en/decrypted.
// TODO: Enforce at API level.
pub fn gcm_128_authenticate_data_once(
    comptime cipher_key_size: usize,
    cipher_encrypt_fn: gcm_128_cipher_fn_t(cipher_key_size),
    ctx: *Gcm128Ctx(cipher_key_size, cipher_encrypt_fn),
    data: []const u8,
) !void {
    // The maximum bit length of the AAD is 2^64.
    if (data.len >= Gcm128Ctx.AAD_MAX_BYTES)
        return CryptoError.MessageLengthLimitExceeded;

    // Compute and store `X_m` where m is the length in blocks of the AAD.
    gcm_128_ghash_padded_chunk(&std.mem.zeroes([]u8), &ctx.h, data, &ctx.ghash_x);

    // Store the AAD length for the tag computation.
    ctx.aad_length = data.len;
}

pub fn gcm_128_encrypt(
    comptime cipher_key_size: usize,
    cipher_encrypt_fn: gcm_128_cipher_fn_t(cipher_key_size),
    ctx: *Gcm128Ctx(cipher_key_size, cipher_encrypt_fn),
    plaintext: []const u8,
    ciphertext: []u8,
) !void {
    if (plaintext.len != ciphertext.len)
        return CryptoError.BufferSizeMismatch;

    if (ctx.ciphertext_length + plaintext.len >= @TypeOf(ctx.*).TEXT_MAX_BYTES)
        return CryptoError.MessageLengthLimitExceeded;

    const BS = GCM_128_BLOCK_SIZE;
    var bytes_processed: usize = 0;

    const bytes_buffered_ct = ctx.ciphertext_length % BS;

    // If we're not at the beginning of a new block, use the existing keystream to encrypt the plaintext.
    if (bytes_buffered_ct != 0) {
        // Simplest case - no block border is reached - just XOR-encrypt and we're done.
        if (bytes_buffered_ct + plaintext.len < BS) {
            gcm_128_crypt_xor(
                @TypeOf(ctx.*).KEY_SIZE,
                @TypeOf(ctx.*).CIPHER_FN,
                ctx,
                plaintext,
                ciphertext,
                false,
            );
            return;
        }
        // Otherwise, encrypt the remainder of the block with the existing
        // keystream and then authenticate the completed ciphertext block.
        else {
            gcm_128_crypt_xor(
                @TypeOf(ctx.*).KEY_SIZE,
                @TypeOf(ctx.*).CIPHER_FN,
                ctx,
                plaintext[0 .. BS - bytes_buffered_ct],
                ciphertext[0 .. BS - bytes_buffered_ct],
                false,
            );
            gcm_128_authenticate_ciphertext_block(
                @TypeOf(ctx.*).KEY_SIZE,
                @TypeOf(ctx.*).CIPHER_FN,
                ctx,
            );
            bytes_processed += BS - bytes_buffered_ct;
        }
    }

    // As long as we have another whole block worth of plaintext, encrypt it
    // and authenticate the CT.
    while ((plaintext.len - bytes_processed) / BS > 0) : (bytes_processed += BS) {
        gcm_128_update_keystream(
            @TypeOf(ctx.*).KEY_SIZE,
            @TypeOf(ctx.*).CIPHER_FN,
            ctx,
        );
        gcm_128_crypt_xor(
            @TypeOf(ctx.*).KEY_SIZE,
            @TypeOf(ctx.*).CIPHER_FN,
            ctx,
            plaintext[bytes_processed .. bytes_processed + BS],
            ciphertext[bytes_processed .. bytes_processed + BS],
            false,
        );
        gcm_128_authenticate_ciphertext_block(
            @TypeOf(ctx.*).KEY_SIZE,
            @TypeOf(ctx.*).CIPHER_FN,
            ctx,
        );
    }

    // Finally, if there's still plaintext left, update the keystream and encrypt the rest of it.
    if (bytes_processed < plaintext.len) {
        gcm_128_update_keystream(
            @TypeOf(ctx.*).KEY_SIZE,
            @TypeOf(ctx.*).CIPHER_FN,
            ctx,
        );
        gcm_128_crypt_xor(
            @TypeOf(ctx.*).KEY_SIZE,
            @TypeOf(ctx.*).CIPHER_FN,
            ctx,
            plaintext[bytes_processed..],
            ciphertext[bytes_processed..],
            false,
        );
        bytes_processed += plaintext.len - bytes_processed;
    }
}

fn gcm_128_crypt_xor(
    comptime cipher_key_size: usize,
    cipher_encrypt_fn: gcm_128_cipher_fn_t(cipher_key_size),
    ctx: *Gcm128Ctx(cipher_key_size, cipher_encrypt_fn),
    input_slice: []const u8,
    output_slice: []u8,
    decrypt: bool,
) void {
    const block_offset = ctx.ciphertext_length % GCM_128_BLOCK_SIZE;

    if (input_slice.len != output_slice.len or
        block_offset + input_slice.len > GCM_128_BLOCK_SIZE)
        @panic("gcm_128_crypt_xor contract violated!");

    const len = input_slice.len;
    for (0..len, block_offset..block_offset + len) |ct_i, ks_i| {
        ctx.ciphertext_buffer[ks_i] = if (decrypt)
            input_slice[ct_i]
        else
            input_slice[ct_i] ^ ctx.keystream[ks_i];

        output_slice[ct_i] = ctx.ciphertext_buffer[ks_i];
    }
    ctx.ciphertext_length += len;
}

fn gcm_128_update_keystream(
    comptime cipher_key_size: usize,
    cipher_encrypt_fn: gcm_128_cipher_fn_t(cipher_key_size),
    ctx: *Gcm128Ctx(cipher_key_size, cipher_encrypt_fn),
) void {
    gcm_128_incr(&ctx.counter);
    cipher_encrypt_fn(&ctx.key, &ctx.counter, &ctx.keystream);
}

fn gcm_128_authenticate_ciphertext_block(
    comptime cipher_key_size: usize,
    cipher_encrypt_fn: gcm_128_cipher_fn_t(cipher_key_size),
    ctx: *Gcm128Ctx(cipher_key_size, cipher_encrypt_fn),
) void {
    xor(GCM_128_BLOCK_SIZE, &ctx.ghash_x, &ctx.ciphertext_buffer, &ctx.ghash_x);
    gcm_128_mult(&ctx.ghash_x, &ctx.h, &ctx.ghash_x);
}

pub fn gcm_128_encrypt_final(
    comptime cipher_key_size: usize,
    cipher_encrypt_fn: gcm_128_cipher_fn_t(cipher_key_size),
    ctx: *Gcm128Ctx(cipher_key_size, cipher_encrypt_fn),
    tag: []u8,
) !void {
    if (tag.len > @TypeOf(ctx.*).TAG_MAX_BYTES)
        return CryptoError.InvalidTagLength;

    // The last ciphertext block is 0-padded and authenticated.
    const ct_residue_bytes = ctx.ciphertext_length % GCM_128_BLOCK_SIZE;
    @memset(ctx.ciphertext_buffer[ct_residue_bytes..], 0);
    gcm_128_authenticate_ciphertext_block(
        @TypeOf(ctx.*).KEY_SIZE,
        @TypeOf(ctx.*).CIPHER_FN,
        ctx,
    );

    // Lastly, authenticate the lengths of the AAD and the ciphertext.
    std.mem.writeInt(u64, ctx.ciphertext_buffer[0..8], ctx.aad_length, .big);
    std.mem.writeInt(u64, ctx.ciphertext_buffer[8..], ctx.ciphertext_length, .big);
    gcm_128_authenticate_ciphertext_block(
        @TypeOf(ctx.*).KEY_SIZE,
        @TypeOf(ctx.*).CIPHER_FN,
        ctx,
    );

    // The authentication tag is the [tag.len] leftmost bytes of the final `X` XORed with `H`.
    xor(GCM_128_BLOCK_SIZE, &ctx.ghash_x, &ctx.h, &ctx.ghash_x);
    @memcpy(tag[0..], ctx.ghash_x[0..tag.len]);
}

pub fn gcm_128_incr(ctr: *[GCM_128_BLOCK_SIZE]u8) void {
    const val32 = std.mem.readInt(u32, ctr[ctr.len - 4 .. ctr.len], .big);
    std.mem.writeInt(u32, ctr[ctr.len - 4 .. ctr.len], val32 +% 1, .big);
}

pub fn gcm_128_ghash_padded_chunk(
    iv: *const [GCM_128_BLOCK_SIZE]u8,
    h: *const [GCM_128_BLOCK_SIZE]u8,
    chunk: []const u8,
    out: *[GCM_128_BLOCK_SIZE]u8,
) void {
    const BS = GCM_128_BLOCK_SIZE;

    const m = chunk.len / BS;
    // Note: This definition of `v` is different from the one in the standard,
    // it is the number of residue *bytes* in the last block, not bits.
    const v = chunk.len % BS;

    var x_i: [GCM_128_BLOCK_SIZE]u8 = iv.*;
    var i: usize = 0;

    while (i < m) : (i += 1) {
        xor(BS, x_i[0..], @ptrCast(chunk[i * BS .. (i + 1) * BS]), &x_i);
        gcm_128_mult(&x_i, h, &x_i);
    }

    var padded: [GCM_128_BLOCK_SIZE]u8 = undefined;
    @memcpy(padded[0..v], chunk[i * BS ..]);
    @memset(padded[v..], 0x00);

    xor(BS, x_i[0..], padded[0..], &x_i);
    gcm_128_mult(&x_i, h, out);
}

pub fn gcm_128_ghash(
    h: *const [GCM_128_BLOCK_SIZE]u8,
    aad_chunk: []const u8,
    ciphertext_chunk: []const u8,
    out: *[GCM_128_BLOCK_SIZE]u8,
) void {
    gcm_128_ghash_padded_chunk(&std.mem.zeroes([GCM_128_BLOCK_SIZE]u8), h, aad_chunk, out);
    gcm_128_ghash_padded_chunk(out, h, ciphertext_chunk, out);

    const BS = GCM_128_BLOCK_SIZE;

    var lengths: [BS]u8 = undefined;
    std.mem.writeInt(u64, lengths[0 .. BS / 2], aad_chunk.len * 8, .big);
    std.mem.writeInt(u64, lengths[BS / 2 ..], ciphertext_chunk.len * 8, .big);

    xor(BS, lengths[0..], out[0..], out);
    gcm_128_mult(out, h, out);
}

// TODO: Naive algorithm: implement optimized versions with table lookups.
pub fn gcm_128_mult(
    a: *const [128 / 8]u8,
    b: *const [128 / 8]u8,
    out: *[128 / 8]u8,
) void {
    const gcm_128_irreducible_R: u128 = 0xe100_0000_0000_0000_0000_0000_0000_0000;

    var z: u128 = 0;
    var v: u128 = std.mem.readInt(u128, a, .big);
    const y: u128 = std.mem.readInt(u128, b, .big);

    for (0..128) |i| {
        const bit_index = 127 - @as(u7, @intCast(i));
        if ((y >> bit_index) & 1 == 1)
            z ^= v;

        if (v & 1 == 0)
            v = v >> 1
        else
            v = (v >> 1) ^ gcm_128_irreducible_R;
    }

    std.mem.writeInt(u128, out, z, .big);
}

fn xor(L: comptime_int, a: *const [L]u8, b: *const [L]u8, out: *[L]u8) void {
    for (0..L) |i|
        out[i] = a[i] ^ b[i];
}

inline fn bytes_from_be_int(Int: type, value: Int) [@sizeOf(Int)]u8 {
    var res: [@sizeOf(Int)]u8 = undefined;
    std.mem.writeInt(Int, &res, value, .big);
    return res;
}

const aes = @import("aes.zig");

// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
test "AES-GCM Test Case 1" {
    const K = bytes_from_be_int(u128, 0x00000000000000000000000000000000);
    const P = [0]u8{};
    const IV = std.mem.zeroes([96 / 8]u8);
    const H = bytes_from_be_int(u128, 0x66e94bd4ef8a2c3b884cfa59ca342b2e);
    const Y0 = bytes_from_be_int(u128, 0x00000000000000000000000000000001);
    // const E_K_Y0 = bytes_from_be_int(u128, 0x58e2fccefa7e3061367f1d57a4e7455a);
    // const len_A_len_C = bytes_from_be_int(u128, 0x00000000000000000000000000000000);
    // const GHASH_H_A_C = bytes_from_be_int(u128, 0x00000000000000000000000000000000);
    const C = [0]u8{};
    const T = bytes_from_be_int(u128, 0x58e2fccefa7e3061367f1d57a4e7455a);

    var ctx = try gcm_128_new(
        aes.Aes128Parameters.KEY_SIZE,
        aes.aes_128_encrypt_block,
        &K,
        &IV,
    );

    try testing.expectEqualSlices(u8, &H, &ctx.h);
    try testing.expectEqualSlices(u8, &Y0, &ctx.counter);

    var ciphertext_buffer = [0]u8{};
    try gcm_128_encrypt(
        aes.Aes128Parameters.KEY_SIZE,
        aes.aes_128_encrypt_block,
        &ctx,
        &P,
        &ciphertext_buffer,
    );
    try testing.expectEqualSlices(u8, &C, &ciphertext_buffer);

    var tag_buffer: @TypeOf(T) = undefined;
    try gcm_128_encrypt_final(
        aes.Aes128Parameters.KEY_SIZE,
        aes.aes_128_encrypt_block,
        &ctx,
        &tag_buffer,
    );
    try testing.expectEqualSlices(u8, &T, &tag_buffer);
}
