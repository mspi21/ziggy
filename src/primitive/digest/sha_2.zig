const std = @import("std");
const testing = std.testing;

const sha = @import("./sha_core.zig");

const builtin = @import("builtin");
const dbg = builtin.mode == std.builtin.Mode.Debug;

pub const SHA_224_DIGEST_LENGTH = 224 / 8;
pub const SHA_224_MESSAGE_BITS_LIMIT = 1 << 64;

pub const SHA_256_DIGEST_LENGTH = 256 / 8;
pub const SHA_256_MESSAGE_BITS_LIMIT = 1 << 64;

pub const Sha2Ctx = struct {
    pub const BLOCK_SIZE = 512 / 8;
    pub const MESSAGE_SCHEDULE_WORDS = 64;
    pub const WordType = u32;

    hash: [SHA_256_DIGEST_LENGTH / @sizeOf(WordType)]WordType,
    message_buffer: [BLOCK_SIZE]u8,
    message_length: u64,

    t_is_224: bool,
};

const SHA_224_IV = [_]u32{
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
};
const SHA_256_IV = [_]u32{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

pub fn sha2_new(t: comptime_int) Sha2Ctx {
    if (comptime t != 224 and t != 256)
        @compileError("SHA-2 context can only be initialized in 224-bit and 256-bit mode.");

    var ctx = Sha2Ctx{
        .hash = undefined,
        .message_buffer = undefined,
        .message_length = 0,
        .t_is_224 = (t == 224),
    };
    @memcpy(&ctx.hash, if (t == 224) &SHA_224_IV else &SHA_256_IV);

    return ctx;
}

pub fn sha2_update(ctx: *Sha2Ctx, message: []const u8) !void {
    // All variants of SHA-2 can digest a message of a maximum length of (2^64 - 1) bits
    // due to the nature of its padding (which is identical to SHA-1).
    return sha.generic_update(
        Sha2Ctx,
        1 << 64,
        &sha2_compress_block,
        ctx,
        message,
    );
}

pub fn sha2_final(ctx: *Sha2Ctx, digest_length: comptime_int, out: *[digest_length]u8) void {
    return sha.generic_final(
        Sha2Ctx,
        Sha2Ctx.WordType,
        u64,
        digest_length,
        &sha2_compress_block,
        ctx,
        out,
    );
}
fn sha2_compress_block(ctx: *Sha2Ctx) void {
    // Prepare the message schedule.
    var message_schedule: [Sha2Ctx.MESSAGE_SCHEDULE_WORDS]u32 = undefined;

    for (0..Sha2Ctx.BLOCK_SIZE / @sizeOf(Sha2Ctx.WordType)) |t|
        message_schedule[t] = sha.deserialize_int_big_endian(
            Sha2Ctx.WordType,
            @ptrCast(ctx.message_buffer[(t * @sizeOf(Sha2Ctx.WordType))..((t + 1) * @sizeOf(Sha2Ctx.WordType))]),
        );
    for (Sha2Ctx.BLOCK_SIZE / @sizeOf(Sha2Ctx.WordType)..Sha2Ctx.MESSAGE_SCHEDULE_WORDS) |t| {
        message_schedule[t] = sha2_sigma_256_1(message_schedule[t - 2]) +% message_schedule[t - 7] +% sha2_sigma_256_0(message_schedule[t - 15]) +% message_schedule[t - 16];
    }

    // Initialize working variables.
    var a = ctx.hash[0];
    var b = ctx.hash[1];
    var c = ctx.hash[2];
    var d = ctx.hash[3];
    var e = ctx.hash[4];
    var f = ctx.hash[5];
    var g = ctx.hash[6];
    var h = ctx.hash[7];

    // Perform the actual hashing.
    inline for (0..Sha2Ctx.MESSAGE_SCHEDULE_WORDS) |t| {
        const tmp1 = h +% sha2_Sigma_256_1(e) +% sha.ch(Sha2Ctx.WordType, e, f, g) +% SHA2_K_256[t] +% message_schedule[t];
        const tmp2 = sha2_Sigma_256_0(a) +% sha.maj(Sha2Ctx.WordType, a, b, c);
        h = g;
        g = f;
        f = e;
        e = d +% tmp1;
        d = c;
        c = b;
        b = a;
        a = tmp1 +% tmp2;
    }

    // Add the result to the previous hash state.
    ctx.hash[0] +%= a;
    ctx.hash[1] +%= b;
    ctx.hash[2] +%= c;
    ctx.hash[3] +%= d;
    ctx.hash[4] +%= e;
    ctx.hash[5] +%= f;
    ctx.hash[6] +%= g;
    ctx.hash[7] +%= h;
}

const SHA2_K_256 = [Sha2Ctx.MESSAGE_SCHEDULE_WORDS]u32{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

fn sha2_Sigma_256_0(x: u32) u32 {
    return sha.rotr(u32, x, 2) ^ sha.rotr(u32, x, 13) ^ sha.rotr(u32, x, 22);
}

fn sha2_Sigma_256_1(x: u32) u32 {
    return sha.rotr(u32, x, 6) ^ sha.rotr(u32, x, 11) ^ sha.rotr(u32, x, 25);
}

fn sha2_sigma_256_0(x: u32) u32 {
    return sha.rotr(u32, x, 7) ^ sha.rotr(u32, x, 18) ^ sha.shr(u32, x, 3);
}

fn sha2_sigma_256_1(x: u32) u32 {
    return sha.rotr(u32, x, 17) ^ sha.rotr(u32, x, 19) ^ sha.shr(u32, x, 10);
}

pub fn sha224_new() Sha2Ctx {
    return sha2_new(224);
}

pub fn sha224_update(ctx: *Sha2Ctx, message: []const u8) !void {
    if (dbg and !ctx.t_is_224)
        @panic("Debug: Attempt to call sha224_update on a SHA-256 context.");
    return sha2_update(ctx, message);
}

pub fn sha224_final(ctx: *Sha2Ctx, out: *[SHA_224_DIGEST_LENGTH]u8) void {
    if (dbg and !ctx.t_is_224)
        @panic("Debug: Attempt to call sha224_final on a SHA-256 context.");
    return sha2_final(ctx, SHA_224_DIGEST_LENGTH, out);
}

pub fn sha256_new() Sha2Ctx {
    return sha2_new(256);
}

pub fn sha256_update(ctx: *Sha2Ctx, message: []const u8) !void {
    if (dbg and ctx.t_is_224)
        @panic("Debug: Attempt to call sha256_update on a SHA-224 context.");
    return sha2_update(ctx, message);
}

pub fn sha256_final(ctx: *Sha2Ctx, out: *[SHA_256_DIGEST_LENGTH]u8) void {
    if (dbg and ctx.t_is_224)
        @panic("Debug: Attempt to call sha256_final on a SHA-224 context.");
    return sha2_final(ctx, SHA_256_DIGEST_LENGTH, out);
}

// https://www.di-mgt.com.au/sha_testvectors.html
test "SHA-224 basic test" {
    try sha.run_hash_precomputed_tests(
        Sha2Ctx,
        SHA_224_DIGEST_LENGTH,
        sha224_new,
        sha224_update,
        sha224_final,
        &.{
            .{ .message = "", .hash = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f" },
            .{ .message = "abc", .hash = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" },
            .{
                .message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                .hash = "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
            },
            .{
                .message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                .hash = "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3",
            },
        },
    );
}

test "SHA-224 padding test" {
    // Here we test every possible length of the message in the last block
    // to make sure that the padding is correct in every single case.

    // The following are the hashes of the ASCII strings '', 'a', 'aa', etc.
    // up until 63 (= [SHA-224 block size in bits] / 8 - 1) concatenated 'a's.
    const reference = [64]*const [2 * SHA_224_DIGEST_LENGTH]u8{ "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5", "2ef29e646f6de95de993a59eb1a94cbf52986892949a0abc015a01f7", "ed782653bfec275cf37d027511a68cece08d1e53df1360c762ce043a", "fb56e0a07d1d4ba4a73d42a07d671f65f96513dc12f9d25f2b5ee86e", "04c15392c64c3db52f9a7fcfb7c0c370900e0308007617899430d088", "2886915dd9dedb0ce015f500ffb570901a69a8357728f893eef45344", "b1de26e908098a9b462c11fdd577613d356a7ff06ddb42fda3ab002b", "57dde80cb5dd10cee89424d7d9d8c4fd7949c882da78110e660dec06", "be63cd48d0b068927261c401a33a386136911c3420a5c335e00599fd", "194c4c5045aee1019b77cb1be88ac68034eb2ddd5a8368054141a11f", "5fa4fb5daff0a9b069061839e5605caff0446465f82268775a226333", "85e4d4fcca88691c8008ce19bd9a3de6b9814dd055c8d21bfd4037bb", "da79142fa39f7f11b990aa9dc4994b6e9ce49454058d5423869acf4c", "bd3278d31dec829db380cfe7d7100fecb4b853f054684687f4c27717", "e541fff1289f562eff589da3c8358d91e4dd589bf5dcc37555eb84fe", "0e0a4176c0c6966926acc6fccd2febd418a407df26f76645139d1320", "d5f1096a707710cf5038ed370f7839543eaea0ed054c7484319e2f9c", "e3a0b5557f7894cbb18d6ed06268242212f098d61e179e80a5e96dbc", "fbb6819175a23811c01073f6142af14e80f2d0c598bed6649f307e1f", "43586eff52cbaf9f22482f34a9437ff45bd2e7312ad586b3dd82802f", "2b9d728b01e2c27a40c5fc27d51d5c93f6a160f0f25da8d924e2b570", "eb7ff45dd3d5871ffd6aee24400367cc835aa0d2311d46b2a48b0424", "ac4f39fb481df8f86b6ddf6e527e61893d259b49810416584b468d22", "c4da7f3f63b9da485b734a270f1af6d132b15f177e06445faec5586b", "91a67814117203c32cfc333869bc74f8c721c10672c3516042d88a0b", "7824f1cc7591643231cefe91bbf6fa88b233bf1e8229a59a2cd01c15", "735d169738ebd05edc44cc49a6a99352815cafec12c10d5bd27e8359", "919523d5847d1ee4f9d72f6bd86e3d1bfb785831237a9d580b87448c", "4c166aebdf561231f2b679d8e8457667c0f374043de76d8e7306cb49", "31723190cc4bc6ae686caeea44c54b7b50e30941b8dca3404fe180d8", "f9b67111fdab7e860d1dbe801efa9b75b563e0ee606a9cbabc1288b9", "37e7740b3af132a8edc5e1636817ce1625b831e0ffd47e5c93d4e3b8", "21093fb6a83a36a2b55afa76da42d66de4ebc3b99fb340739d068500", "62d7fcd624a2c1d674ead77584bd66e06d2a6ed160702a594dd6a26e", "507fba56abf0fe3856d0d61527d2a96b18e234bad594bdc969fbfdf4", "6d3a8a79bcc6222986f3b3f17b716774de66d321d51ec34e49995b18", "b622cd8b687970603662b70401a36e464f6860ad337be21c86f17dce", "9c63438f755166862211cc708592f918d31c24e7e70080d6d08e3685", "0126a8fdfaea25bb65fa0b8d6586cd64eee956369b5d2c814607e9f9", "47e263d6419979086bd9a8c4f93591cba373912b68e2ae86085bd2df", "7d8c659cacc50ffc474948b79d65ed98bdab16f6b8a511d184593c86", "da1619b92df1a450be79a14a21e270cb2257230f7dfdc61128e0b49e", "babea0fecfea0aa82d1580abca47dad191f5b9d5a51788d64f678393", "61dd4e5d414a5ae61e76a9b7524223f3cdaf7c9c02b73c175b3e03dd", "fc50179169329ce825404d027fdab44058efc9f28ccddd694a31960e", "b5b7bef9dba5e6a57cecdc03d9a539667f3ca131343de3b6763d7463", "58756e846cce4e08b2ae1103ec3dd2c5755c15f94c1127782dde82c5", "73e0009122e9f4d311459277b81009e9cecc4b3dccf785d4ad476a14", "c0af565a56aeccfd2d40455f20d2c9431a7ab88c61e94973c97cff91", "df427221dc453d5c1466081d9d6e9da3155d5d0dff2a90eb0425036c", "7820fc9fc80c5ed788738da53fbfa6cf1fa981d656a3bb1e68cdf281", "163a72bc0462179bf0486f8a139da514913670d12bbe1d84efc44556", "3fae7c2d692c1610c4a20a17a790d256c3b0071bcdf6fb7fb9538681", "282e1dec88fa36a1070631cca69e3c08a5e18e29fb0b6f6927fbcc0d", "fb0bd626a70c28541dfa781bb5cc4d7d7f56622a58f01a0b1ddd646f", "d40854fc9caf172067136f2e29e1380b14626bf6f0dd06779f820dcd", "b5d09534784ab6578128bce7f28a96a56e3b45c4f734f74739076249", "00df3f1eaa489fd28a9de6e6d7b55402c4e3a56928c5043d77240237", "a82137820aaae9e66f277c3a9254f4a6078c47b410bc9d9a761c2e0b", "efda4316fe2d457d622cf1fc42993d41566f77449b7494b38e250c41", "54e3b540f6792b6a4570f5225717686fbf670fd0dfd3802e4ace9d77", "0daa67402af98b9988c65471b2589dbcdd8bb39569ed77c592aca4a4", "1d4e051f4d6fed2a63fd2421e65834cec00d64456553de3496ae8b1d" };

    var digest_buffer: [SHA_224_DIGEST_LENGTH]u8 = undefined;
    for (0..64) |i| {
        var ctx = sha224_new();
        for (0..i) |_|
            try sha224_update(&ctx, "a");
        sha224_final(&ctx, &digest_buffer);

        const ref = sha.hex_to_bytes(SHA_224_DIGEST_LENGTH, reference[i]);
        try testing.expectEqualSlices(u8, ref[0..], digest_buffer[0..]);
    }
}

test "SHA-224 maximum length violation (simulated)" {
    var ctx = sha224_new();
    ctx.message_length = (1 << 61) - 1; // 2^64 - 8 bits
    try testing.expectError(sha.MessageLengthLimitExceeded, sha224_update(&ctx, "a"));
}

// https://www.di-mgt.com.au/sha_testvectors.html
test "SHA-256 basic test" {
    try sha.run_hash_precomputed_tests(
        Sha2Ctx,
        SHA_256_DIGEST_LENGTH,
        sha256_new,
        sha256_update,
        sha256_final,
        &.{
            .{ .message = "", .hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
            .{ .message = "abc", .hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
            .{
                .message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                .hash = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            },
            .{
                .message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                .hash = "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
            },
        },
    );
}

test "SHA-256 padding test" {
    // Here we test every possible length of the message in the last block
    // to make sure that the padding is correct in every single case.

    // The following are the hashes of the ASCII strings '', 'a', 'aa', etc.
    // up until 63 (= [SHA-256 block size in bits] / 8 - 1) concatenated 'a's.
    const reference = [64]*const [2 * SHA_256_DIGEST_LENGTH]u8{ "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", "961b6dd3ede3cb8ecbaacbd68de040cd78eb2ed5889130cceb4c49268ea4d506", "9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0", "61be55a8e2f6b4e172338bddf184d6dbee29c98853e0a0485ecee7f27b9af0b4", "ed968e840d10d2d313a870bc131a4e2c311d7ad09bdf32b3418147221f51a6e2", "ed02457b5c41d964dbd2f2a609d63fe1bb7528dbe55e1abf5b52c249cd735797", "e46240714b5db3a23eee60479a623efba4d633d27fe4f03c904b9e219a7fbe60", "1f3ce40415a2081fa3eee75fc39fff8e56c22270d1a978a7249b592dcebd20b4", "f2aca93b80cae681221f0445fa4e2cae8a1f9f8fa1e1741d9639caad222f537d", "bf2cb58a68f684d95a3b78ef8f661c9a4e5b09e82cc8f9cc88cce90528caeb27", "28cb017dfc99073aa1b47c1b30f413e3ce774c4991eb4158de50f9dbb36d8043", "f24abc34b13fade76e805799f71187da6cd90b9cac373ae65ed57f143bd664e5", "a689d786e81340e45511dec6c7ab2d978434e5db123362450fe10cfac70d19d0", "82cab7df0abfb9d95dca4e5937ce2968c798c726fea48c016bf9763221efda13", "ef2df0b539c6c23de0f4cbe42648c301ae0e22e887340a4599fb4ef4e2678e48", "0c0beacef8877bbf2416eb00f2b5dc96354e26dd1df5517320459b1236860f8c", "b860666ee2966dd8f903be44ee605c6e1366f926d9f17a8f49937d11624eb99d", "c926defaaa3d13eda2fc63a553bb7fb7326bece6e7cb67ca5296e4727d89bab4", "a0b4aaab8a966e2193ba172d68162c4656860197f256b5f45f0203397ff3f99c", "42492da06234ad0ac76f5d5debdb6d1ae027cffbe746a1c13b89bb8bc0139137", "7df8e299c834de198e264c3e374bc58ecd9382252a705c183beb02f275571e3b", "ec7c494df6d2a7ea36668d656e6b8979e33641bfea378c15038af3964db057a3", "897d3e95b65f26676081f8b9f3a98b6ee4424566303e8d4e7c7522ebae219eab", "09f61f8d9cd65e6a0c258087c485b6293541364e42bd97b2d7936580c8aa3c54", "2f521e2a7d0bd812cbc035f4ed6806eb8d851793b04ba147e8f66b72f5d1f20f", "9976d549a25115dab4e36d0c1fb8f31cb07da87dd83275977360eb7dc09e88de", "cc0616e61cbd6e8e5e34e9fb2d320f37de915820206f5696c31f1fbd24aa16de", "9c547cb8115a44883b9f70ba68f75117cd55359c92611875e386f8af98c172ab", "6913c9c7fd42fe23df8b6bcd4dbaf1c17748948d97f2980b432319c39eddcf6c", "3a54fc0cbc0b0ef48b6507b7788096235d10292dd3ae24e22f5aa062d4f9864a", "61c60b487d1a921e0bcc9bf853dda0fb159b30bf57b2e2d2c753b00be15b5a09", "3ba3f5f43b92602683c19aee62a20342b084dd5971ddd33808d81a328879a547", "852785c805c77e71a22340a54e9d95933ed49121e7d2bf3c2d358854bc1359ea", "a27c896c4859204843166af66f0e902b9c3b3ed6d2fd13d435abc020065c526f", "629362afc62c74497caed2272e30f8125ecd0965f8d8d7cfc4e260f7f8dd319d", "22c1d24bcd03e9aee9832efccd6da613fc702793178e5f12c945c7b67ddda933", "21ec055b38ce759cd4d0f477e9bdec2c5b8199945db4439bae334a964df6246c", "365a9c3e2c2af0a56e47a9dac51c2c5381bf8f41273bad3175e0e619126ad087", "b4d5e56e929ba4cda349e9274e3603d0be246b82016bca20f363963c5f2d6845", "e33cdf9c7f7120b98e8c78408953e07f2ecd183006b5606df349b4c212acf43e", "c0f8bd4dbc2b0c03107c1c37913f2a7501f521467f45dd0fef6958e9a4692719", "7a538607fdaab9296995929f451565bbb8142e1844117322aafd2b3d76b01aff", "66d34fba71f8f450f7e45598853e53bfc23bbd129027cbb131a2f4ffd7878cd0", "16849877c6c21ef0bfa68e4f6747300ddb171b170b9f00e189edc4c2fc4db93e", "52789e3423b72beeb898456a4f49662e46b0cbb960784c5ef4b1399d327e7c27", "6643110c5628fff59edf76d82d5bf573bf800f16a4d65dfb1e5d6f1a46296d0b", "11eaed932c6c6fddfc2efc394e609facf4abe814fc6180d03b14fce13a07d0e5", "97daac0ee9998dfcad6c9c0970da5ca411c86233a944c25b47566f6a7bc1ddd5", "8f9bec6a62dd28ebd36d1227745592de6658b36974a3bb98a4c582f683ea6c42", "160b4e433e384e05e537dc59b467f7cb2403f0214db15c5db58862a3f1156d2e", "bfc5fe0e360152ca98c50fab4ed7e3078c17debc2917740d5000913b686ca129", "6c1b3dc7a706b9dc81352a6716b9c666c608d8626272c64b914ab05572fc6e84", "abe346a7259fc90b4c27185419628e5e6af6466b1ae9b5446cac4bfc26cf05c4", "a3f01b6939256127582ac8ae9fb47a382a244680806a3f613a118851c1ca1d47", "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318", "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a", "f13b2d724659eb3bf47f2dd6af1accc87b81f09f59f2b75e5c0bed6589dfe8c6", "d5c039b748aa64665782974ec3dc3025c042edf54dcdc2b5de31385b094cb678", "111bb261277afd65f0744b247cd3e47d386d71563d0ed995517807d5ebd4fba3", "11ee391211c6256460b6ed375957fadd8061cafbb31daf967db875aebd5aaad4", "35d5fc17cfbbadd00f5e710ada39f194c5ad7c766ad67072245f1fad45f0f530", "f506898cc7c2e092f9eb9fadae7ba50383f5b46a2a4fe5597dbb553a78981268", "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34" };

    var digest_buffer: [SHA_256_DIGEST_LENGTH]u8 = undefined;
    for (0..64) |i| {
        var ctx = sha256_new();
        for (0..i) |_|
            try sha256_update(&ctx, "a");
        sha256_final(&ctx, &digest_buffer);

        const ref = sha.hex_to_bytes(SHA_256_DIGEST_LENGTH, reference[i]);
        try testing.expectEqualSlices(u8, ref[0..], digest_buffer[0..]);
    }
}

test "SHA-256 maximum length violation (simulated)" {
    var ctx = sha256_new();
    ctx.message_length = (1 << 61) - 1; // 2^64 - 8 bits
    try testing.expectError(sha.MessageLengthLimitExceeded, sha256_update(&ctx, "a"));
}
