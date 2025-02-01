const std = @import("std");
const testing = std.testing;

const salsa20 = @import("primitive").streamcipher.salsa20;

// https://cr.yp.to/snuffle/spec.pdf
test "Salsa20 quarterround function" {
    try test_quarter_round_function(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    try test_quarter_round_function(0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x08008145, 0x00000080, 0x00010200, 0x20500000);
    try test_quarter_round_function(0x00000000, 0x00000001, 0x00000000, 0x00000000, 0x88000100, 0x00000001, 0x00000200, 0x00402000);
    try test_quarter_round_function(0x00000000, 0x00000000, 0x00000001, 0x00000000, 0x80040000, 0x00000000, 0x00000001, 0x00002000);
    try test_quarter_round_function(0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00048044, 0x00000080, 0x00010000, 0x20100001);
    try test_quarter_round_function(0xe7e8c006, 0xc4f9417d, 0x6479b4b2, 0x68c67137, 0xe876d72b, 0x9361dfd5, 0xf1460244, 0x948541a3);
    try test_quarter_round_function(0xd3917c5b, 0x55f1c407, 0x52a58a7a, 0x8f887a3b, 0x3e2f308c, 0xd90a8f36, 0x6ab2a923, 0x2883524c);
}

// https://cr.yp.to/snuffle/spec.pdf
test "Salsa20 rowround function" {
    var y1 = [_]u32{
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
    };
    const z1 = [_]u32{
        0x08008145, 0x00000080, 0x00010200, 0x20500000,
        0x20100001, 0x00048044, 0x00000080, 0x00010000,
        0x00000001, 0x00002000, 0x80040000, 0x00000000,
        0x00000001, 0x00000200, 0x00402000, 0x88000100,
    };
    salsa20.row_round(&y1);
    try testing.expectEqualSlices(u32, z1[0..], y1[0..]);

    var y2 = [_]u32{
        0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
        0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
        0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
        0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a,
    };
    const z2 = [_]u32{
        0xa890d39d, 0x65d71596, 0xe9487daa, 0xc8ca6a86,
        0x949d2192, 0x764b7754, 0xe408d9b9, 0x7a41b4d1,
        0x3402e183, 0x3c3af432, 0x50669f96, 0xd89ef0a8,
        0x0040ede5, 0xb545fbce, 0xd257ed4f, 0x1818882d,
    };
    salsa20.row_round(&y2);
    try testing.expectEqualSlices(u32, z2[0..], y2[0..]);
}

// https://cr.yp.to/snuffle/spec.pdf
test "Salsa20 columnround function" {
    var x1 = [_]u32{
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
    };
    const y1 = [_]u32{
        0x10090288, 0x00000000, 0x00000000, 0x00000000,
        0x00000101, 0x00000000, 0x00000000, 0x00000000,
        0x00020401, 0x00000000, 0x00000000, 0x00000000,
        0x40a04001, 0x00000000, 0x00000000, 0x00000000,
    };
    salsa20.column_round(&x1);
    try testing.expectEqualSlices(u32, y1[0..], x1[0..]);

    var x2 = [_]u32{
        0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
        0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
        0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
        0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a,
    };
    const y2 = [_]u32{
        0x8c9d190a, 0xce8e4c90, 0x1ef8e9d3, 0x1326a71a,
        0x90a20123, 0xead3c4f3, 0x63a091a0, 0xf0708d69,
        0x789b010c, 0xd195a681, 0xeb7d5504, 0xa774135c,
        0x481c2027, 0x53a8e4b5, 0x4c1f89c5, 0x3f78c9c8,
    };
    salsa20.column_round(&x2);
    try testing.expectEqualSlices(u32, y2[0..], x2[0..]);
}

// https://cr.yp.to/snuffle/spec.pdf
test "Salsa20 doubleround function" {
    var x1 = [_]u32{
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
    };
    const z1 = [_]u32{
        0x8186a22d, 0x0040a284, 0x82479210, 0x06929051,
        0x08000090, 0x02402200, 0x00004000, 0x00800000,
        0x00010200, 0x20400000, 0x08008104, 0x00000000,
        0x20500000, 0xa0000040, 0x0008180a, 0x612a8020,
    };
    salsa20.double_round(&x1);
    try testing.expectEqualSlices(u32, z1[0..], x1[0..]);

    var x2 = [_]u32{
        0xde501066, 0x6f9eb8f7, 0xe4fbbd9b, 0x454e3f57,
        0xb75540d3, 0x43e93a4c, 0x3a6f2aa0, 0x726d6b36,
        0x9243f484, 0x9145d1e8, 0x4fa9d247, 0xdc8dee11,
        0x054bf545, 0x254dd653, 0xd9421b6d, 0x67b276c1,
    };
    const z2 = [_]u32{
        0xccaaf672, 0x23d960f7, 0x9153e63a, 0xcd9a60d0,
        0x50440492, 0xf07cad19, 0xae344aa0, 0xdf4cfdfc,
        0xca531c29, 0x8e7943db, 0xac1680cd, 0xd503ca00,
        0xa74b2ad6, 0xbc331c5c, 0x1dda24c7, 0xee928277,
    };
    salsa20.double_round(&x2);
    try testing.expectEqualSlices(u32, z2[0..], x2[0..]);
}

// https://cr.yp.to/snuffle/spec.pdf
test "Salsa20 hash function" {
    try test_hash_function(1, &std.mem.zeroes([salsa20.BLOCK_SIZE]u8), &std.mem.zeroes([salsa20.BLOCK_SIZE]u8));
    try test_hash_function(1, &.{
        211, 159, 13,  115, 76, 55,  82,  183, 3,   117, 222, 37,  191, 187, 234, 136,
        49,  237, 179, 48,  1,  106, 178, 219, 175, 199, 166, 48,  86,  16,  179, 207,
        31,  240, 32,  63,  15, 83,  93,  161, 116, 147, 48,  113, 238, 55,  204, 36,
        79,  201, 235, 79,  3,  81,  156, 47,  203, 26,  244, 243, 88,  118, 104, 54,
    }, &.{
        109, 42,  178, 168, 156, 240, 248, 238, 168, 196, 190, 203, 26,  110, 170, 154,
        29,  29,  150, 26,  150, 30,  235, 249, 190, 163, 251, 48,  69,  144, 51,  57,
        118, 40,  152, 157, 180, 57,  27,  94,  107, 42,  236, 35,  27,  111, 114, 114,
        219, 236, 232, 135, 111, 155, 110, 18,  24,  232, 95,  158, 179, 19,  48,  202,
    });
    try test_hash_function(1, &.{
        88,  118, 104, 54,  79,  201, 235, 79,  3,  81,  156, 47,  203, 26,  244, 243,
        191, 187, 234, 136, 211, 159, 13,  115, 76, 55,  82,  183, 3,   117, 222, 37,
        86,  16,  179, 207, 49,  237, 179, 48,  1,  106, 178, 219, 175, 199, 166, 48,
        238, 55,  204, 36,  31,  240, 32,  63,  15, 83,  93,  161, 116, 147, 48,  113,
    }, &.{
        179, 19,  48,  202, 219, 236, 232, 135, 111, 155, 110, 18,  24,  232, 95,  158,
        26,  110, 170, 154, 109, 42,  178, 168, 156, 240, 248, 238, 168, 196, 190, 203,
        69,  144, 51,  57,  29,  29,  150, 26,  150, 30,  235, 249, 190, 163, 251, 48,
        27,  111, 114, 114, 118, 40,  152, 157, 180, 57,  27,  94,  107, 42,  236, 35,
    });
    try test_hash_function(1000000, &.{
        6,   124, 83,  146, 38,  191, 9,  50,  4,   161, 47,  222, 122, 182, 223, 185,
        75,  27,  0,   216, 16,  122, 7,  89,  162, 104, 101, 147, 213, 21,  54,  95,
        225, 253, 139, 176, 105, 132, 23, 116, 76,  41,  176, 207, 221, 34,  157, 108,
        94,  94,  99,  52,  90,  117, 91, 220, 146, 190, 239, 143, 196, 176, 130, 186,
    }, &.{
        8,   18,  38,  199, 119, 76,  215, 67,  173, 127, 144, 162, 103, 212, 176, 217,
        192, 19,  233, 33,  159, 197, 154, 160, 128, 243, 219, 65,  171, 136, 135, 225,
        123, 11,  68,  86,  237, 82,  20,  155, 133, 189, 9,   83,  167, 116, 194, 78,
        122, 127, 195, 185, 185, 204, 188, 90,  245, 9,   183, 248, 226, 85,  245, 104,
    });
}

// https://cr.yp.to/snuffle/spec.pdf
test "Salsa20 expansion function" {
    const key1 = [salsa20.KEY_SIZE]u8{
        1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  15,  16,
        201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216,
    };
    const nonce1 = [salsa20.NONCE_SIZE]u8{ 101, 102, 103, 104, 105, 106, 107, 108 };
    const pos1 = [salsa20.NONCE_SIZE]u8{ 109, 110, 111, 112, 113, 114, 115, 116 };
    const reference1 = [salsa20.BLOCK_SIZE]u8{
        69,  37,  68,  39,  41,  15,  107, 193, 255, 139, 122, 6,   170, 233, 217, 98,
        89,  144, 182, 106, 21,  51,  200, 65,  239, 49,  222, 34,  215, 114, 40,  126,
        104, 197, 7,   225, 197, 153, 31,  2,   102, 78,  76,  176, 84,  245, 246, 184,
        177, 160, 133, 130, 6,   72,  149, 119, 192, 195, 132, 236, 234, 103, 246, 74,
    };

    var ctx1 = salsa20.salsa20_new(&key1, &nonce1, &pos1, &salsa20.CONSTANTS_256);
    defer salsa20.salsa20_destroy(&ctx1);

    var keystream_buffer: [salsa20.BLOCK_SIZE]u8 = undefined;
    salsa20.serialize(salsa20.BLOCK_WORDS, ctx1.state[0..], keystream_buffer[0..]);

    try testing.expectEqualSlices(u8, reference1[0..], keystream_buffer[0..]);

    const key2 = [salsa20.KEY_SIZE]u8{
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    };
    const reference2 = [salsa20.BLOCK_SIZE]u8{
        39,  173, 46,  248, 30,  200, 82,  17,  48,  67, 254, 239, 37,  18,  13,  247,
        241, 200, 61,  144, 10,  55,  50,  185, 6,   47, 246, 253, 143, 86,  187, 225,
        134, 85,  110, 246, 161, 163, 43,  235, 231, 94, 171, 51,  145, 214, 112, 29,
        14,  232, 5,   16,  151, 140, 183, 141, 171, 9,  122, 181, 104, 182, 177, 193,
    };

    var ctx2 = salsa20.salsa20_new(&key2, &nonce1, &pos1, &salsa20.CONSTANTS_128);
    defer salsa20.salsa20_destroy(&ctx2);

    salsa20.serialize(salsa20.BLOCK_WORDS, ctx2.state[0..], keystream_buffer[0..]);
    try testing.expectEqualSlices(u8, reference2[0..], keystream_buffer[0..]);
}

test "Salsa20 encryption" {
    const key = [salsa20.KEY_SIZE]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const nonce = [salsa20.NONCE_SIZE]u8{
        0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    };
    const counter = std.mem.zeroes([salsa20.COUNTER_SIZE]u8);
    const plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const reference = [_]u8{
        0x13, 0xfc, 0x5e, 0x28, 0x51, 0xf0, 0x79, 0x9d, 0x97, 0x52, 0x1b, 0xa6, 0xa9, 0x37, 0x11, 0x87,
        0x00, 0x95, 0x7c, 0x2e, 0xf9, 0x96, 0xe4, 0x2c, 0x59, 0x84, 0x9d, 0x45, 0x0c, 0x6e, 0xa2, 0x2e,
        0x91, 0xcd, 0xcc, 0xea, 0x39, 0x1e, 0xe0, 0xa3, 0x57, 0xbb, 0x56, 0xcd, 0xf5, 0x2c, 0x56, 0xce,
        0x01, 0x38, 0x07, 0xa9, 0x45, 0xb9, 0x17, 0xee, 0x6c, 0xcb, 0x18, 0xce, 0xca, 0xbe, 0x4b, 0xf4,
        0x09, 0xba, 0x72, 0xfb, 0xdf, 0x90, 0xdb, 0x02, 0x8d, 0x22, 0x61, 0x7f, 0x1c, 0xa9, 0x84, 0x15,
        0x6c, 0xa2, 0x72, 0x47, 0x3a, 0xf4, 0xf0, 0xe4, 0xcb, 0x3d, 0x85, 0x8b, 0x7a, 0xb4, 0x67, 0xae,
        0x14, 0x71, 0x87, 0xab, 0xac, 0xb7, 0xc6, 0xe9, 0xaf, 0x6f, 0x2f, 0x47, 0x28, 0x7e, 0x2e, 0x0c,
        0xb3, 0x18,
    };

    var ctx = salsa20.salsa20_new(&key, &nonce, &counter, &salsa20.CONSTANTS_256);
    defer salsa20.salsa20_destroy(&ctx);

    var buffer: [plaintext.len]u8 = undefined;
    @memcpy(&buffer, plaintext);

    try salsa20.encrypt_inplace(&ctx, &buffer);
    try testing.expectEqualSlices(u8, reference[0..], buffer[0..]);
}

// ----------------------------------- TEST HELPERS ----------------------------------- //

fn test_quarter_round_function(y0: u32, y1: u32, y2: u32, y3: u32, z0: u32, z1: u32, z2: u32, z3: u32) !void {
    var dummy_state: [salsa20.BLOCK_WORDS]u32 = undefined;
    dummy_state[0] = y0;
    dummy_state[1] = y1;
    dummy_state[2] = y2;
    dummy_state[3] = y3;
    salsa20.quarter_round(&dummy_state, 0, 1, 2, 3);
    try testing.expectEqualSlices(u32, &.{ z0, z1, z2, z3 }, dummy_state[0..4]);
}

fn test_hash_function(count: comptime_int, input: *const [salsa20.BLOCK_SIZE]u8, reference: *const [salsa20.BLOCK_SIZE]u8) !void {
    var dummy_ctx = salsa20.Salsa20Ctx{
        .key = undefined,
        .nonce = undefined,
        .counter = undefined,
        .constants = undefined,
        .state = undefined,
        .working_state = undefined,
        .keystream_idx = undefined,
    };

    salsa20.deserialize(salsa20.BLOCK_WORDS, input, dummy_ctx.state[0..]);
    for (0..count) |_|
        salsa20.hash_function(&dummy_ctx);

    var serialized_result: [salsa20.BLOCK_SIZE]u8 = undefined;
    salsa20.serialize(salsa20.BLOCK_WORDS, dummy_ctx.state[0..], serialized_result[0..]);

    try testing.expectEqualSlices(u8, reference, serialized_result[0..]);
}
