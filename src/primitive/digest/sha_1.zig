const std = @import("std");
const testing = std.testing;

const sha = @import("./sha_core.zig");

pub const SHA_1_DIGEST_LENGTH = 160 / 8;
pub const SHA_1_MESSAGE_BITS_LIMIT = 1 << 64;

pub const Sha1Ctx = struct {
    pub const BLOCK_SIZE = 512 / 8;
    pub const MESSAGE_SCHEDULE_WORDS = 80;
    pub const WordType = u32;

    hash: [SHA_1_DIGEST_LENGTH / @sizeOf(WordType)]WordType,
    message_buffer: [BLOCK_SIZE]u8,
    message_length: u64,
};

const SHA_1_IV = [_]u32{
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
};

pub fn sha1_new() Sha1Ctx {
    var ctx = Sha1Ctx{
        .hash = undefined,
        .message_buffer = undefined,
        .message_length = 0,
    };
    @memcpy(&ctx.hash, &SHA_1_IV);
    return ctx;
}

pub fn sha1_update(ctx: *Sha1Ctx, message: []const u8) !void {
    return sha.generic_update(
        Sha1Ctx,
        SHA_1_MESSAGE_BITS_LIMIT,
        &sha1_compress_block,
        ctx,
        message,
    );
}

pub fn sha1_final(ctx: *Sha1Ctx, out: *[SHA_1_DIGEST_LENGTH]u8) void {
    return sha.generic_final(
        Sha1Ctx,
        Sha1Ctx.WordType,
        u64,
        SHA_1_DIGEST_LENGTH,
        sha1_compress_block,
        ctx,
        out,
    );
}

pub fn sha1_compress_block(ctx: *Sha1Ctx) void {
    // Prepare the message schedule.
    var message_schedule: [Sha1Ctx.MESSAGE_SCHEDULE_WORDS]Sha1Ctx.WordType = undefined;

    for (0..Sha1Ctx.BLOCK_SIZE / @sizeOf(Sha1Ctx.WordType)) |t|
        message_schedule[t] = sha.deserialize_int_big_endian(u32, @ptrCast(ctx.message_buffer[(t * 4)..(t * 4 + 4)]));
    for (Sha1Ctx.BLOCK_SIZE / @sizeOf(Sha1Ctx.WordType)..Sha1Ctx.MESSAGE_SCHEDULE_WORDS) |t| {
        message_schedule[t] = sha.rotl(
            Sha1Ctx.WordType,
            message_schedule[t - 3] ^ message_schedule[t - 8] ^ message_schedule[t - 14] ^ message_schedule[t - 16],
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
        const tmp = sha.rotl(Sha1Ctx.WordType, a, 5) +% sha1_f(t, b, c, d) +% e +% sha1_k(t) +% message_schedule[t];
        e = d;
        d = c;
        c = sha.rotl(Sha1Ctx.WordType, b, 30);
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
        0...19 => sha.ch(u32, x, y, z),
        20...39 => sha.parity(u32, x, y, z),
        40...59 => sha.maj(u32, x, y, z),
        60...79 => sha.parity(u32, x, y, z),
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

// https://www.di-mgt.com.au/sha_testvectors.html
test "SHA-1 basic test" {
    try sha.run_hash_precomputed_tests(
        Sha1Ctx,
        SHA_1_DIGEST_LENGTH,
        sha1_new,
        sha1_update,
        sha1_final,
        &.{
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
        },
    );
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

        const ref = sha.hex_to_bytes(SHA_1_DIGEST_LENGTH, reference[i]);
        try testing.expectEqualSlices(u8, ref[0..], digest_buffer[0..]);
    }
}

test "SHA-1 maximum length violation (simulated)" {
    var ctx = sha1_new();
    ctx.message_length = (1 << 61) - 1; // 2^64 - 8 bits
    try testing.expectError(sha.MessageLengthLimitExceeded, sha1_update(&ctx, "a"));
}
