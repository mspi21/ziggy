const std = @import("std");
const testing = std.testing;

const CryptoError = error{
    MessageLengthLimitExceeded,
    BufferSizeMismatch,
    InvalidIVLength,
    InvalidTagLength,
    IncorrectAuthenticationTag,
};

pub const GCM128_BLOCK_SIZE = 128 / 8;

pub fn gcm128_cipher_fn_t(comptime key_size: usize) type {
    return fn (
        key: *const [key_size]u8,
        block_in: *const [GCM128_BLOCK_SIZE]u8,
        block_out: *[GCM128_BLOCK_SIZE]u8,
    ) void;
}

fn Gcm128Ctx(
    comptime cipher_key_size: usize,
    cipher_encrypt_fn: gcm128_cipher_fn_t(cipher_key_size),
) type {
    return struct {
        const BLOCK_SIZE = GCM128_BLOCK_SIZE;
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
        y0: [BLOCK_SIZE]u8,
        ciphertext_buffer: [BLOCK_SIZE]u8,
        ciphertext_length: u64,
        aad_length: u64,
    };
}

pub fn gcm128_new(
    comptime cipher_key_size: usize,
    cipher_encrypt_fn: gcm128_cipher_fn_t(cipher_key_size),
    key: *const [cipher_key_size]u8,
    iv: []const u8,
) !Gcm128Ctx(cipher_key_size, cipher_encrypt_fn) {
    if (iv.len == 0)
        return CryptoError.InvalidIVLength;

    var ctx = Gcm128Ctx(cipher_key_size, cipher_encrypt_fn){
        .key = undefined,
        .keystream = undefined,
        .counter = undefined,
        .ghash_x = undefined,
        .h = undefined,
        .y0 = undefined,
        .ciphertext_buffer = undefined,
        .ciphertext_length = 0,
        .aad_length = 0,
    };

    // Set the encryption/decryption key.
    @memcpy(&ctx.key, key);

    // Compute the `H` value.
    cipher_encrypt_fn(&ctx.key, &std.mem.zeroes([GCM128_BLOCK_SIZE]u8), &ctx.h);

    // Set the counter initial value (`Y_0`).
    if (iv.len == 96 / 8) {
        @memcpy(ctx.counter[0 .. 96 / 8], iv);
        @memset(ctx.counter[(96 / 8)..(ctx.counter.len - 1)], 0x00);
        ctx.counter[ctx.counter.len - 1] = 0x01;
    } else {
        gcm128_ghash(&ctx.h, &.{}, iv, &ctx.counter);
    }
    @memcpy(&ctx.y0, &ctx.counter);

    return ctx;
}

pub fn gcm128_destroy(
    comptime cipher_key_size: usize,
    cipher_encrypt_fn: gcm128_cipher_fn_t(cipher_key_size),
    ctx: *Gcm128Ctx(cipher_key_size, cipher_encrypt_fn),
) void {
    @memset(&ctx, 0);
}

// Important: this function must only be called at most once
// AFTER the context is initialized but BEFORE any data is en/decrypted.
// TODO: Enforce at API level.
pub fn gcm128_authenticate_data_once(
    comptime cipher_key_size: usize,
    cipher_encrypt_fn: gcm128_cipher_fn_t(cipher_key_size),
    ctx: *Gcm128Ctx(cipher_key_size, cipher_encrypt_fn),
    data: []const u8,
) !void {
    // The maximum bit length of the AAD is 2^64.
    if (data.len >= Gcm128Ctx.AAD_MAX_BYTES)
        return CryptoError.MessageLengthLimitExceeded;

    // Compute and store `X_m` where m is the length in blocks of the AAD.
    gcm128_ghash_pad_chunk(&std.mem.zeroes([]u8), &ctx.h, data, &ctx.ghash_x);

    // Store the AAD length for the tag computation.
    ctx.aad_length = data.len;
}

pub fn gcm128_encrypt(
    comptime cipher_key_size: usize,
    cipher_encrypt_fn: gcm128_cipher_fn_t(cipher_key_size),
    ctx: *Gcm128Ctx(cipher_key_size, cipher_encrypt_fn),
    plaintext: []const u8,
    ciphertext: []u8,
) !void {
    if (plaintext.len != ciphertext.len)
        return CryptoError.BufferSizeMismatch;

    if (ctx.ciphertext_length + plaintext.len >= @TypeOf(ctx.*).TEXT_MAX_BYTES)
        return CryptoError.MessageLengthLimitExceeded;

    const BS = GCM128_BLOCK_SIZE;
    const KS = @TypeOf(ctx.*).KEY_SIZE;
    const ENC = @TypeOf(ctx.*).CIPHER_FN;

    const bytes_buffered_ct = ctx.ciphertext_length % BS;
    var bytes_processed: usize = 0;

    // If we're not at the beginning of a new block, use the existing keystream to encrypt the plaintext.
    if (bytes_buffered_ct != 0) {
        // Simplest case - no block border is reached - just XOR-encrypt and we're done.
        if (bytes_buffered_ct + plaintext.len < BS) {
            return gcm128_crypt_xor(KS, ENC, ctx, plaintext, ciphertext, false);
        }
        // Otherwise, encrypt the remainder of the block with the existing
        // keystream and then authenticate the completed ciphertext block.
        else {
            const len = BS - bytes_buffered_ct;
            gcm128_crypt_xor(KS, ENC, ctx, plaintext[0..len], ciphertext[0..len], false);
            gcm128_authenticate_ciphertext_block(KS, ENC, ctx);
            bytes_processed += BS - bytes_buffered_ct;
        }
    }

    // As long as we have another whole block worth of plaintext, encrypt it
    // and authenticate the CT.
    while ((plaintext.len - bytes_processed) / BS > 0) : (bytes_processed += BS) {
        const start = bytes_processed;
        const end = bytes_processed + BS;
        gcm128_update_keystream(KS, ENC, ctx);
        gcm128_crypt_xor(KS, ENC, ctx, plaintext[start..end], ciphertext[start..end], false);
        gcm128_authenticate_ciphertext_block(KS, ENC, ctx);
    }

    // Finally, if there's still plaintext left, update the keystream and encrypt the rest of it.
    if (bytes_processed < plaintext.len) {
        gcm128_update_keystream(KS, ENC, ctx);
        gcm128_crypt_xor(KS, ENC, ctx, plaintext[bytes_processed..], ciphertext[bytes_processed..], false);
        bytes_processed += plaintext.len - bytes_processed;
    }
}

fn gcm128_crypt_xor(
    comptime cipher_key_size: usize,
    cipher_encrypt_fn: gcm128_cipher_fn_t(cipher_key_size),
    ctx: *Gcm128Ctx(cipher_key_size, cipher_encrypt_fn),
    input_slice: []const u8,
    output_slice: []u8,
    decrypt: bool,
) void {
    const block_offset = ctx.ciphertext_length % GCM128_BLOCK_SIZE;

    if (input_slice.len != output_slice.len or
        block_offset + input_slice.len > GCM128_BLOCK_SIZE)
        @panic("gcm128_crypt_xor contract violated!");

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

fn gcm128_update_keystream(
    comptime cipher_key_size: usize,
    cipher_encrypt_fn: gcm128_cipher_fn_t(cipher_key_size),
    ctx: *Gcm128Ctx(cipher_key_size, cipher_encrypt_fn),
) void {
    gcm128_incr(&ctx.counter);
    cipher_encrypt_fn(&ctx.key, &ctx.counter, &ctx.keystream);
}

fn gcm128_authenticate_ciphertext_block(
    comptime cipher_key_size: usize,
    cipher_encrypt_fn: gcm128_cipher_fn_t(cipher_key_size),
    ctx: *Gcm128Ctx(cipher_key_size, cipher_encrypt_fn),
) void {
    xor(GCM128_BLOCK_SIZE, &ctx.ghash_x, &ctx.ciphertext_buffer, &ctx.ghash_x);
    gcm128_mult(&ctx.ghash_x, &ctx.h, &ctx.ghash_x);
}

pub fn gcm128_encrypt_final(
    comptime cipher_key_size: usize,
    cipher_encrypt_fn: gcm128_cipher_fn_t(cipher_key_size),
    ctx: *Gcm128Ctx(cipher_key_size, cipher_encrypt_fn),
    tag: []u8,
) !void {
    if (tag.len > @TypeOf(ctx.*).TAG_MAX_BYTES)
        return CryptoError.InvalidTagLength;

    const KS = @TypeOf(ctx.*).KEY_SIZE;
    const ENC = @TypeOf(ctx.*).CIPHER_FN;

    // The last ciphertext block is 0-padded and authenticated.
    const ct_residue_bytes = ctx.ciphertext_length % GCM128_BLOCK_SIZE;
    @memset(ctx.ciphertext_buffer[ct_residue_bytes..], 0);
    gcm128_authenticate_ciphertext_block(KS, ENC, ctx);

    // Lastly, authenticate the lengths of the AAD and the ciphertext.
    std.mem.writeInt(u64, ctx.ciphertext_buffer[0..8], ctx.aad_length, .big);
    std.mem.writeInt(u64, ctx.ciphertext_buffer[8..], ctx.ciphertext_length, .big);
    gcm128_authenticate_ciphertext_block(KS, ENC, ctx);

    // The authentication tag is the [tag.len] leftmost bytes of the final `X` XORed with `E(K,Y0)`.
    cipher_encrypt_fn(&ctx.key, &ctx.y0, &ctx.keystream);
    xor(GCM128_BLOCK_SIZE, &ctx.ghash_x, &ctx.keystream, &ctx.ghash_x);

    @memcpy(tag[0..], ctx.ghash_x[0..tag.len]);
}

pub fn gcm128_incr(ctr: *[GCM128_BLOCK_SIZE]u8) void {
    const val32 = std.mem.readInt(u32, ctr[ctr.len - 4 .. ctr.len], .big);
    std.mem.writeInt(u32, ctr[ctr.len - 4 .. ctr.len], val32 +% 1, .big);
}

pub fn gcm128_ghash_pad_chunk(
    iv: *const [GCM128_BLOCK_SIZE]u8,
    h: *const [GCM128_BLOCK_SIZE]u8,
    chunk: []const u8,
    out: *[GCM128_BLOCK_SIZE]u8,
) void {
    const BS = GCM128_BLOCK_SIZE;

    const m = chunk.len / BS;
    // Note: This definition of `v` is different from the one in the standard,
    // it is the number of residue *bytes* in the last block, not bits.
    const v = chunk.len % BS;

    var x_i: [GCM128_BLOCK_SIZE]u8 = iv.*;
    var i: usize = 0;

    while (i < m) : (i += 1) {
        xor(BS, x_i[0..], @ptrCast(chunk[i * BS .. (i + 1) * BS]), &x_i);
        gcm128_mult(&x_i, h, &x_i);
    }

    var padded: [GCM128_BLOCK_SIZE]u8 = undefined;
    @memcpy(padded[0..v], chunk[i * BS ..]);
    @memset(padded[v..], 0x00);

    xor(BS, x_i[0..], padded[0..], &x_i);
    gcm128_mult(&x_i, h, out);
}

pub fn gcm128_ghash(
    h: *const [GCM128_BLOCK_SIZE]u8,
    aad_chunk: []const u8,
    ciphertext_chunk: []const u8,
    out: *[GCM128_BLOCK_SIZE]u8,
) void {
    gcm128_ghash_pad_chunk(&std.mem.zeroes([GCM128_BLOCK_SIZE]u8), h, aad_chunk, out);
    gcm128_ghash_pad_chunk(out, h, ciphertext_chunk, out);

    const BS = GCM128_BLOCK_SIZE;

    var lengths: [BS]u8 = undefined;
    std.mem.writeInt(u64, lengths[0 .. BS / 2], aad_chunk.len * 8, .big);
    std.mem.writeInt(u64, lengths[BS / 2 ..], ciphertext_chunk.len * 8, .big);

    xor(BS, lengths[0..], out[0..], out);
    gcm128_mult(out, h, out);
}

// TODO: Naive algorithm: implement optimized versions with table lookups.
pub fn gcm128_mult(
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
