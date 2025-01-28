const std = @import("std");
const testing = std.testing;

// ----------------------------------- ERROR DEFINITIONS -----------------------------------  //

pub const MessageLengthLimitExceeded = error.MessageLengthLimitExceeded;

// ----------------------------------- SHA CONSTANTS -----------------------------------  //

//pub const ShaAlgorithm = enum { Sha1, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256 };

const SHA_1_DIGEST_LENGTH = 160 / 8;
const SHA_224_DIGEST_LENGTH = 224 / 8;
const SHA_256_DIGEST_LENGTH = 256 / 8;
const SHA_384_DIGEST_LENGTH = 384 / 8;
const SHA_512_DIGEST_LENGTH = 512 / 8;
const SHA_512_224_DIGEST_LENGTH = 224 / 8;
const SHA_512_256_DIGEST_LENGTH = 256 / 8;

const SHA_1_IV = [_]u32{
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
};
const SHA_224_IV = [_]u32{
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
};
const SHA_256_IV = [_]u32{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};
const SHA_384_IV = [_]u64{
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
};
const SHA_512_IV = [_]u64{
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
};
const SHA_512_224_IV = [_]u64{
    0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF,
    0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1,
};
const SHA_512_256_IV = [_]u64{
    0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD,
    0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2,
};

// ----------------------------------- SHA ALGORITHMS -----------------------------------  //

const Sha1Ctx = struct {
    const BLOCK_SIZE = 512 / 8;
    const MESSAGE_SCHEDULE_WORDS = 80;

    message_schedule: [MESSAGE_SCHEDULE_WORDS]u32,
    hash: [SHA_1_DIGEST_LENGTH / 4]u32,
    message_buffer: [BLOCK_SIZE]u8,
    message_length: u64,
};

const Sha2Ctx = struct {
    const BLOCK_SIZE = 512 / 8;

    message_schedule: [16]u32,
    hash: [8]u32,
    message_buffer: [BLOCK_SIZE]u8,
    message_length: u64,

    t_is_224: bool,
};

const Sha3Ctx = struct {
    const BLOCK_SIZE = 1024 / 8;

    message_schedule: [16]u64,
    hash: [8]u64,
    message_buffer: [BLOCK_SIZE]u8,
    message_length: u128,

    // I could generalize this in the future, like decribed in the standard.
    t_is_224: bool,
    t_is_256: bool,
    t_is_384: bool,
};

pub fn sha1_new() Sha1Ctx {
    var ctx = Sha1Ctx{
        .message_schedule = undefined,
        .hash = undefined,
        .message_buffer = undefined,
        .message_length = 0,
    };
    @memcpy(&ctx.hash, &SHA_1_IV);
    return ctx;
}

pub fn sha1_update(ctx: *Sha1Ctx, message: []const u8) !void {
    // SHA-1 can digest a message of a maximum length of (2^64 - 1) bits due to the nature of its padding.
    if (ctx.message_length + message.len > ((1 << 64) / 8))
        return MessageLengthLimitExceeded;

    const cnt_buffered_bytes = ctx.message_length % Sha1Ctx.BLOCK_SIZE;

    // Simplest case - the message did not fully fill the block size
    // so it's just copied to the context and no hashing is done yet.
    if (cnt_buffered_bytes + message.len < Sha1Ctx.BLOCK_SIZE) {
        @memcpy(
            ctx.message_buffer[cnt_buffered_bytes .. cnt_buffered_bytes + message.len],
            message[0..],
        );
        ctx.message_length += message.len;
        return;
    }

    // Otherwise: first, copy & hash the first block.
    @memcpy(
        ctx.message_buffer[cnt_buffered_bytes..],
        message[0 .. Sha1Ctx.BLOCK_SIZE - cnt_buffered_bytes],
    );
    sha1_hash_one_block(ctx);
    var cnt_message_bytes_processed = Sha1Ctx.BLOCK_SIZE - cnt_buffered_bytes;
    ctx.message_length += cnt_message_bytes_processed;

    // Then, as long as there is at least another block available, copy and hash it.
    while (message.len - cnt_message_bytes_processed >= Sha1Ctx.BLOCK_SIZE) {
        @memcpy(ctx.message_buffer[0..], message[cnt_message_bytes_processed .. cnt_message_bytes_processed + Sha1Ctx.BLOCK_SIZE]);
        sha1_hash_one_block(ctx);
        ctx.message_length += Sha1Ctx.BLOCK_SIZE;
        cnt_message_bytes_processed += Sha1Ctx.BLOCK_SIZE;
    }

    // Finally, copy any leftover bytes to the context buffer without hashing.
    const cnt_leftover_bytes = message.len - cnt_message_bytes_processed;
    @memcpy(
        ctx.message_buffer[0..cnt_leftover_bytes],
        message[cnt_message_bytes_processed..],
    );
    ctx.message_length += cnt_leftover_bytes;
}

pub fn sha1_final(ctx: *Sha1Ctx, out: *[SHA_1_DIGEST_LENGTH]u8) void {
    // The message length is stored in the padding as a 64-bit int.
    const message_length_bytes = 64 / 8;

    const cnt_leftover_bytes = ctx.message_length % Sha1Ctx.BLOCK_SIZE;

    // Simpler case: The leftover message is shorter than 446 bits
    // (or 55 bytes) and the padding only spans one block.
    if (cnt_leftover_bytes < Sha1Ctx.BLOCK_SIZE - (message_length_bytes)) {
        const cnt_padding_bytes = Sha1Ctx.BLOCK_SIZE - message_length_bytes - cnt_leftover_bytes;

        // The padding (without the message length) is a single 1 bit followed by 0 bits.
        ctx.message_buffer[cnt_leftover_bytes] = 0x80;
        @memset(ctx.message_buffer[cnt_leftover_bytes + 1 .. cnt_leftover_bytes + cnt_padding_bytes], 0x00);

        // The length is appended.
        const length = serialize_int_big_endian(u64, ctx.message_length * 8);
        @memcpy(ctx.message_buffer[cnt_leftover_bytes + cnt_padding_bytes ..], length[0..]);

        // The padded block is finally hashed.
        sha1_hash_one_block(ctx);
    }
    // Otherwise, the padding spans 2 blocks in total
    // and two more hash iterations are performed.
    else {
        // Pad and hash the first block.
        ctx.message_buffer[cnt_leftover_bytes] = 0x80;
        @memset(ctx.message_buffer[cnt_leftover_bytes + 1 ..], 0x00);
        sha1_hash_one_block(ctx);

        // Hash the second block.
        @memset(ctx.message_buffer[0..(Sha1Ctx.BLOCK_SIZE - message_length_bytes)], 0x00);
        const length = serialize_int_big_endian(u64, ctx.message_length * 8);
        @memcpy(ctx.message_buffer[(Sha1Ctx.BLOCK_SIZE - message_length_bytes)..], length[0..]);
        sha1_hash_one_block(ctx);
    }

    // Serialize the result.
    for (0..SHA_1_DIGEST_LENGTH / 4) |w| {
        const serialized_word = serialize_int_big_endian(u32, ctx.hash[w]);
        @memcpy(out[(w * 4)..(w * 4 + 4)], serialized_word[0..]);
    }
}

pub fn sha1_hash_one_block(ctx: *Sha1Ctx) void {
    // Prepare the message schedule.
    for (0..Sha1Ctx.BLOCK_SIZE / 4) |t|
        ctx.message_schedule[t] = deserialize_int_big_endian(u32, @ptrCast(ctx.message_buffer[(t * 4)..(t * 4 + 4)]));
    for (Sha1Ctx.BLOCK_SIZE / 4..Sha1Ctx.MESSAGE_SCHEDULE_WORDS) |t| {
        ctx.message_schedule[t] = rotl(
            u32,
            ctx.message_schedule[t - 3] ^ ctx.message_schedule[t - 8] ^ ctx.message_schedule[t - 14] ^ ctx.message_schedule[t - 16],
            1,
        );
    }

    // Initialize working variables.
    var a = ctx.hash[0];
    var b = ctx.hash[1];
    var c = ctx.hash[2];
    var d = ctx.hash[3];
    var e = ctx.hash[4];

    // Perform the actual hashing.
    inline for (0..Sha1Ctx.MESSAGE_SCHEDULE_WORDS) |t| {
        const tmp = rotl(u32, a, 5) +% sha1_f(t, b, c, d) +% e +% sha1_k(t) +% ctx.message_schedule[t];
        e = d;
        d = c;
        c = rotl(u32, b, 30);
        b = a;
        a = tmp;
    }

    // Add the result to the previous hash state.
    ctx.hash[0] +%= a;
    ctx.hash[1] +%= b;
    ctx.hash[2] +%= c;
    ctx.hash[3] +%= d;
    ctx.hash[4] +%= e;
}

inline fn sha1_f(t: comptime_int, x: u32, y: u32, z: u32) u32 {
    return switch (t) {
        0...19 => ch(u32, x, y, z),
        20...39 => parity(u32, x, y, z),
        40...59 => maj(u32, x, y, z),
        60...79 => parity(u32, x, y, z),
        else => @compileError("SHA-1 `f` function called with invalid value of `t`."),
    };
}

inline fn sha1_k(t: comptime_int) u32 {
    return switch (t) {
        0...19 => 0x5a827999,
        20...39 => 0x6ed9eba1,
        40...59 => 0x8f1bbcdc,
        60...79 => 0xca62c1d6,
        else => @compileError("SHA-1 `k` constant requested with invalid value of `t`."),
    };
}

pub fn sha2_new(t: comptime_int) Sha2Ctx {
    if (comptime t != 224 and t != 256)
        @compileError("SHA-2 context can only be initialized in 224-bit and 256-bit mode.");

    var ctx = Sha2Ctx{
        .message_schedule = undefined,
        .hash = undefined,
        .a = if (t == 224) SHA_224_IV[0] else SHA_256_IV[0],
        .b = if (t == 224) SHA_224_IV[1] else SHA_256_IV[1],
        .c = if (t == 224) SHA_224_IV[2] else SHA_256_IV[2],
        .d = if (t == 224) SHA_224_IV[3] else SHA_256_IV[3],
        .e = if (t == 224) SHA_224_IV[4] else SHA_256_IV[4],
        .f = if (t == 224) SHA_224_IV[5] else SHA_256_IV[5],
        .g = if (t == 224) SHA_224_IV[6] else SHA_256_IV[6],
        .h = if (t == 224) SHA_224_IV[7] else SHA_256_IV[7],
        .message_buffer = undefined,
        .message_length = 0,
        .t_is_224 = (t == 224),
    };
    @memcpy(&ctx.hash, if (t == 224) &SHA_224_IV else &SHA_256_IV);

    return ctx;
}

pub fn sha224_new() Sha2Ctx {
    return sha2_new(224);
}

pub fn sha224_update(ctx: *Sha2Ctx, message: []const u8) !void {
    // TODO
    _ = .{ ctx, message };
}

pub fn sha224_final(ctx: *Sha1Ctx, out: [SHA_224_DIGEST_LENGTH]u8) void {
    // TODO
    _ = .{ ctx, out };
}

pub fn sha256_new() Sha2Ctx {
    return sha2_new(256);
}

pub fn sha256_update(ctx: *Sha2Ctx, message: []const u8) !void {
    // TODO
    _ = .{ ctx, message };
}

pub fn sha256_final(ctx: *Sha2Ctx, out: [SHA_256_DIGEST_LENGTH]u8) void {
    // TODO
    _ = .{ ctx, out };
}

pub fn sha3_new(t: comptime_int) Sha3Ctx {
    if (comptime t != 224 and t != 256 and t != 384 and t != 512)
        @compileError("SHA-3 context can only be initialized in 224, 256, 384 and 512-bit mode.");

    const iv: *const [Sha3Ctx.BLOCK_SIZE]u64 = switch (t) {
        224 => &SHA_512_224_IV,
        256 => &SHA_512_256_IV,
        384 => &SHA_384_IV,
        512 => &SHA_512_IV,
        _ => unreachable,
    };

    var ctx = Sha3Ctx{
        .message_schedule = undefined,
        .hash = undefined,
        .a = iv[0],
        .b = iv[1],
        .c = iv[2],
        .d = iv[3],
        .e = iv[4],
        .f = iv[5],
        .g = iv[6],
        .h = iv[7],
        .message_buffer = undefined,
        .message_length = 0,
        .t_is_224 = (t == 224),
        .t_is_256 = (t == 256),
        .t_is_384 = (t == 384),
    };
    @memcpy(&ctx.hash, iv);

    return ctx;
}

pub fn sha384_new() Sha3Ctx {
    return sha3_new(384);
}

pub fn sha384_update(ctx: *Sha3Ctx, message: []const u8) !void {
    // TODO
    _ = .{ ctx, message };
}

pub fn sha384_final(ctx: *Sha3Ctx, out: [SHA_384_DIGEST_LENGTH]u8) void {
    // TODO
    _ = .{ ctx, out };
}

pub fn sha512_new() Sha3Ctx {
    return sha3_new(512);
}

pub fn sha512_update(ctx: *Sha3Ctx, message: []const u8) !void {
    // TODO
    _ = .{ ctx, message };
}

pub fn sha512_final(ctx: *Sha3Ctx, out: [SHA_512_DIGEST_LENGTH]u8) void {
    // TODO
    _ = .{ ctx, out };
}

pub fn sha512_224_new() Sha3Ctx {
    return sha3_new(224);
}

pub fn sha512_224_update(ctx: *Sha3Ctx, message: []const u8) !void {
    // TODO
    _ = .{ ctx, message };
}

pub fn sha512_224_final(ctx: *Sha3Ctx, out: [SHA_512_224_DIGEST_LENGTH]u8) void {
    // TODO
    _ = .{ ctx, out };
}

pub fn sha512_256_new() Sha3Ctx {
    return sha3_new(256);
}

pub fn sha512_256_update(ctx: *Sha3Ctx, message: []const u8) !void {
    // TODO
    _ = .{ ctx, message };
}

pub fn sha512_256_final(ctx: *Sha3Ctx, out: [SHA_512_256_DIGEST_LENGTH]u8) void {
    // TODO
    _ = .{ ctx, out };
}

// ----------------------------------- Non-linear functions ----------------------------------- //

fn ch(T: type, x: T, y: T, z: T) T {
    return (x & y) ^ (~x & z);
}

fn parity(T: type, x: T, y: T, z: T) T {
    return x ^ y ^ z;
}

fn maj(T: type, x: T, y: T, z: T) T {
    return (x & y) ^ (x & z) ^ (y & z);
}

// ----------------------------------- HELPERS ----------------------------------- //

fn rotl(T: type, word: T, bits: comptime_int) T {
    if (comptime bits >= @bitSizeOf(T))
        @compileError("Will not rotate word left by more bits than it has!");
    return (word << bits) | (word >> (@bitSizeOf(T) - bits));
}

fn serialize_int_big_endian(T: type, int: T) [@sizeOf(T)]u8 {
    var res: [@sizeOf(T)]u8 = undefined;
    for (0..@sizeOf(T)) |i|
        res[i] = @truncate(int >> @intCast(8 * (@sizeOf(T) - i - 1)));
    return res;
}

fn deserialize_int_big_endian(T: type, bytes: *const [@sizeOf(T)]u8) T {
    var res: T = 0;
    for (0..@sizeOf(T)) |i|
        res |= @as(T, bytes[i]) << @intCast(8 * (@sizeOf(T) - i - 1));
    return res;
}

// ----------------------------------- TEST VECTORS ----------------------------------- //

fn hex_nibble_to_int(ascii_hex: u8) u4 {
    const x = ascii_hex;
    return @intCast(if (x >= '0' and x <= '9')
        x - '0'
    else if (x >= 'a' and x <= 'f')
        10 + (x - 'a')
    else if (x >= 'A' and x <= 'F')
        10 + (x - 'A')
    else
        @panic("Argument is not a valid hex digit!"));
}

fn hex_to_bytes(L: comptime_int, hex_string: *const [2 * L]u8) [L]u8 {
    var res: [L]u8 = undefined;
    for (0..L) |i| {
        res[i] = @as(u8, hex_nibble_to_int(hex_string[2 * i])) << 4;
        res[i] |= hex_nibble_to_int(hex_string[2 * i + 1]);
    }
    return res;
}

// https://www.di-mgt.com.au/sha_testvectors.html
test "SHA-1 basic test" {
    const tests = [_]struct {
        message: []const u8,
        hash: *const [2 * SHA_1_DIGEST_LENGTH]u8,
    }{
        .{ .message = "", .hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
        .{ .message = "abc", .hash = "a9993e364706816aba3e25717850c26c9cd0d89d" },
        .{
            .message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            .hash = "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
        },
        .{
            .message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            .hash = "a49b2446a02c645bf419f995b67091253a04a259",
        },
    };

    var digest_buffer: [SHA_1_DIGEST_LENGTH]u8 = undefined;

    for (tests) |t| {
        var ctx = sha1_new();
        try sha1_update(&ctx, t.message);
        sha1_final(&ctx, &digest_buffer);

        const reference = hex_to_bytes(SHA_1_DIGEST_LENGTH, t.hash);
        try testing.expectEqualSlices(u8, reference[0..], digest_buffer[0..]);
    }
}

test "SHA-1 padding test" {
    // Here we test every possible length of the message in the last block
    // to make sure that the padding is correct in every single case.

    // The following are the hashes of the ASCII strings '', 'a', 'aa', etc.
    // up until 63 (= [SHA-1 block size in bits] / 8 - 1) concatenated 'a's.
    const reference = [64]*const [2 * SHA_1_DIGEST_LENGTH]u8{ "da39a3ee5e6b4b0d3255bfef95601890afd80709", "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8", "e0c9035898dd52fc65c41454cec9c4d2611bfb37", "7e240de74fb1ed08fa08d38063f6a6a91462a815", "70c881d4a26984ddce795f6f71817c9cf4480e79", "df51e37c269aa94d38f93e537bf6e2020b21406c", "f7a9e24777ec23212c54d7a350bc5bea5477fdbb", "e93b4e3c464ffd51732fbd6ded717e9efda28aad", "b480c074d6b75947c02681f31c90c668c46bf6b8", "2882f38e575101ba615f725af5e59bf2333a9a68", "3495ff69d34671d1e15b33a63c1379fdedd3a32a", "755c001f4ae3c8843e5a50dd6aa2fa23893dd3ad", "384fcd160ab3b33174ea279ad26052eee191508a", "897b99631295d204db13e863b296a09e70ab1d65", "128c484ff69fcdc1f82cd3781595cac5185e688f", "7e13c003a8256cd421055563c5da6571d50713c9", "3499c60eea227453c779de50fc84e217e9a53a18", "321a618ba6830de900738b0814d0c9f28ff2fece", "0478095c8ece0bbc11f94663ac2c4f10b29666de", "1335bfa62671b0015c6e20766c07035868edb8f4", "38666b8ba500faa5c2406f4575d42a92379844c2", "035a4ee5d60816878caec161d6cb8e00e9cc539b", "8c2a4e5c8f210b6aaa6c95e1c8e21351959f4541", "85e3737bb8ab36e2866501e517c46fffc085313e", "b1c76aec7674865d5346b3b0d1cb2c223c53e73e", "44f4647e1542a79d7d68ceb7f75d1dbf77fdebfc", "de8280c3a1c7db377f1ec7107c7fb62d374cc09c", "52a00b8461593ce33409d7c5d0411699cbf9cda3", "06587751ce11a8703abc64cab55b0b96d88341aa", "498a75f314a645671bc79a118df385d0d9948484", "cd762363c1c11ecb48611583520bba111f0034d4", "65cf771ad2cc0b1e8f89361e3b7bec2365b3ad24", "68f84a59a3ca2d0e5cb1646fbb164da409b5d8f2", "2368a1ac71c68c4b47b4fb2806508e0eb447aa64", "82d5343f4b2f0fcf6e28672d1f1a10c434f213d5", "f4d3e057abac5109b7e953578fa97968ea34f43a", "6c783ce5cc13ea5ce572eddfaba02f9d1bb90905", "9e55bf6ab8f14b37cc6f69eb7374be6c5cbd2d07", "1290c28910a6c12c9a131f0ecb523114f20f14c2", "4f5fc75bd3c93bccc09fc2de9c95442456053faf", "a56559418dc7908ce5f0b24b05c78e055cb863dc", "52cedd6b110e4330b5186478736afa5203c4f9ea", "32e067e0414932c3edd95fc4176a54bff1ddfe29", "7bd258f2f4cc4b02fca4ea157f55f6d88d26d954", "df51a19b291586bf46450aec1d775f3e02799b55", "4642fe68c57cd01fc68fc11b7f22b940328a7cc4", "03a4de84c189a836eaee643041b34ad2386db70d", "25883f7a0e732e9ab10e594ea59425dfe4d90359", "3e3d6e12b933133de2caa248ea12bd193a67f206", "1e666934c5a35f509aa31bbd9af8a37a1ed13ba6", "6c177354157989a2c6cd7bac80465b13bea25832", "aca32b501c231ef8e2d8703e71415bfbe4ccbc64", "e6479c70bbac662e4cc134cb8bdaade59ff55b66", "d9b66a0801459c8094398ef8f04700a8569c9906", "b05d71c64979cb95fa74a33cdb31a40d258ae02e", "c1c8bbdc22796e28c0e15163d20899b65621d65a", "c2db330f6083854c99d4b5bfb6e8f29f201be699", "f08f24908d682555111be7ff6f004e78283d989a", "5ee0f8895f4e1aae6a6661de5c432e34188a5a2d", "dbc8b8f59ff85a2b1448ed873484b14bf0507246", "13d956033d9af449bfe2c4ef78c17c20469c4bf1", "aeab141db28af3353283b5ccb2a322df0b9b5f56", "67b4b3923fa178d788a9611b76446c96431071f2", "03f09f5b158a7a8cdad920bddc29b81c18a551f5" };

    var digest_buffer: [SHA_1_DIGEST_LENGTH]u8 = undefined;
    for (0..64) |i| {
        var ctx = sha1_new();
        for (0..i) |_|
            try sha1_update(&ctx, "a");
        sha1_final(&ctx, &digest_buffer);

        const ref = hex_to_bytes(SHA_1_DIGEST_LENGTH, reference[i]);
        try testing.expectEqualSlices(u8, ref[0..], digest_buffer[0..]);
    }
}
