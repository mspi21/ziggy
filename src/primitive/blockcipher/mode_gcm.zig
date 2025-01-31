const std = @import("std");

const CryptoError = @import("../../error.zig").CryptoError;

const Gcm128Ctx = struct {
    const BLOCK_SIZE = 128 / 8;

    cipher_key_size: comptime_int,
    cipher_encrypt_fn: fn (*const [.cipher_key_size]u8, *const [BLOCK_SIZE]u8, *[BLOCK_SIZE]u8) void,
    key: [.cipher_key_size]u8,
    counter: [BLOCK_SIZE]u8,
    ghash_x: [BLOCK_SIZE]u8,
    text_buffer: [BLOCK_SIZE]u8,
    text_length: u64,
    aad_length: u64,
};

pub fn gcm_128_new(
    cipher_key_size: comptime_int,
    cipher_encrypt_fn: fn (key: *const [cipher_key_size]u8, block_in: *const [Gcm128Ctx.BLOCK_SIZE]u8, block_out: *[Gcm128Ctx.BLOCK_SIZE]u8) void,
    key: *const [cipher_key_size]u8,
    iv: []const u8,
) Gcm128Ctx {
    if (iv.len == 0) {
        return CryptoError.InvalidIVLength;
    }

    var ctx = Gcm128Ctx{
        .cipher_key_size = cipher_key_size,
        .cipher_encrypt_fn = cipher_encrypt_fn,
        .key = undefined,
        .counter = undefined,
        .ghash_x = undefined,
        .text_buffer = undefined,
        .text_length = 0,
        .aad_length = 0,
    };

    // Set the encryption/decryption key.
    @memcpy(&ctx.key, key);

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

pub fn gcm_128_destroy(ctx: *Gcm128Ctx) void {
    @memset(&ctx, 0);
}

// Important: this function must only be called at most once
// AFTER the context is initialized but BEFORE any data is en/decrypted.
// TODO: Enforce at API level.
pub fn gcm_128_authenticate_data_once(
    ctx: *Gcm128Ctx,
    data: []const u8,
) !void {
    // The maximum bit length of the AAD is 2^64.
    if (data.len > (1 << 61))
        return CryptoError.MessageLengthLimitExceeded;

    // Compute `H` temporarily.
    const h = std.mem.zeroes([Gcm128Ctx.BLOCK_SIZE]u8);
    ctx.cipher_encrypt_fn(&ctx.key, &h, &h);

    // Since `H` depends on the key, destroy it before leaving the function.
    defer @memset(&h, 0);

    // Compute and store `X_m` where m is the length in blocks of the AAD.
    gcm_128_ghash_padded_chunk(&std.mem.zeroes([]u8), &h, data, &ctx.ghash_x);

    // Store the AAD length for the tag computation.
    ctx.aad_length = data.len;
}

pub fn gcm_128_encrypt(ctx: *Gcm128Ctx, plaintext: []const u8, ciphertext: []u8) void {
    if (plaintext.len != ciphertext.len)
        return CryptoError.BufferSizeMismatch;

    // TODO
    _ = .{ ctx, plaintext, ciphertext };
}

pub fn gcm_128_encrypt_final(ctx: *Gcm128Ctx, tag_length: u4, tag: []u8) void {
    // TODO
    _ = .{ ctx, tag_length, tag };
}

pub fn gcm_128_incr(ctr: *[Gcm128Ctx.BLOCK_SIZE]u8) void {
    const val32 = std.mem.readInt(u32, ctr[ctr.len - 4 .. ctr.len], .big);
    std.mem.writeInt(u32, ctr[ctr.len - 4 .. ctr.len], val32 +% 1, .big);
}

pub fn gcm_128_ghash_padded_chunk(
    iv: *const [Gcm128Ctx.BLOCK_SIZE]u8,
    h: *const [Gcm128Ctx.BLOCK_SIZE]u8,
    chunk: []const u8,
    out: *[Gcm128Ctx.BLOCK_SIZE]u8,
) void {
    const bs = Gcm128Ctx.BLOCK_SIZE;

    const m = chunk.len / bs;
    // Note: This definition of `v` is different from the one in the standard,
    // it is the number of residue *bytes* in the last block, not bits.
    const v = chunk.len % bs;

    var x_i: [Gcm128Ctx.BLOCK_SIZE]u8 = *iv;
    var i: usize = 0;

    while (i < m) : (i += 1) {
        xor(bs, x_i[0..], chunk[i * bs .. (i + 1) * bs], &x_i);
        gcm_128_mult(&x_i, h, &x_i);
    }

    var padded: [Gcm128Ctx.BLOCK_SIZE]u8 = undefined;
    @memcpy(padded[0..v], chunk[i * bs ..]);
    @memset(padded[v..], 0x00);

    xor(bs, x_i[0..], padded[0..], &x_i);
    gcm_128_mult(&x_i, h, out);
}

pub fn gcm_128_ghash(
    h: *const [Gcm128Ctx.BLOCK_SIZE]u8,
    aad_chunk: []const u8,
    ciphertext_chunk: []const u8,
    out: *[Gcm128Ctx.BLOCK_SIZE]u8,
) void {
    gcm_128_ghash_padded_chunk(&std.mem.zeroes([Gcm128Ctx.BLOCK_SIZE]u8), h, aad_chunk, out);
    gcm_128_ghash_padded_chunk(out, h, ciphertext_chunk, out);

    const bs = Gcm128Ctx.BLOCK_SIZE;

    var lengths: [bs]u8 = undefined;
    std.mem.writeInt(u64, lengths[0 .. bs / 2], aad_chunk.len * 8, .big);
    std.mem.writeInt(u64, lengths[bs / 2 ..], ciphertext_chunk.len * 8, .big);

    xor(bs, lengths[0..], out[0..], out);
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
    var v = std.mem.readInt(u128, a, .big);
    const y = std.mem.readInt(u128, b, .big);

    for (0..128) |i| {
        if ((y >> (127 - i)) & 1 == 1)
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
