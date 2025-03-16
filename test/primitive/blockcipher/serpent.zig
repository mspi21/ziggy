const std = @import("std");
const testing = std.testing;

const serpent = @import("primitive").blockcipher.serpent;

// https://biham.cs.technion.ac.il/Reports/Serpent/Serpent-128-128.verified.test-vectors

test "NESSIE Serpent-128 test vector set 1" {
    try test_encryption(
        &fromhex(16, "80000000000000000000000000000000"),
        &fromhex(16, "00000000000000000000000000000000"),
        &fromhex(16, "264e5481eff42a4606abda06c0bfda3d"),
    );
    try test_encryption(
        &fromhex(16, "40000000000000000000000000000000"),
        &fromhex(16, "00000000000000000000000000000000"),
        &fromhex(16, "4A231B3BC727993407AC6EC8350E8524"),
    );
    try test_encryption(
        &fromhex(16, "20000000000000000000000000000000"),
        &fromhex(16, "00000000000000000000000000000000"),
        &fromhex(16, "E03269F9E9FD853C7D8156DF14B98D56"),
    );
    try test_encryption(
        &fromhex(16, "10000000000000000000000000000000"),
        &fromhex(16, "00000000000000000000000000000000"),
        &fromhex(16, "A798181C3081AC59D5BA89754DACC48F"),
    );
    // TODO: ...
}

test "NESSIE Serpent-128 test vector set 2" {
    try test_encryption(
        &fromhex(16, "00000000000000000000000000000000"),
        &fromhex(16, "80000000000000000000000000000000"),
        &fromhex(16, "A3B35DE7C358DDD82644678C64B8BCBB"),
    );
    try test_encryption(
        &fromhex(16, "00000000000000000000000000000000"),
        &fromhex(16, "40000000000000000000000000000000"),
        &fromhex(16, "04ABCFE4E0AF27FF92A2BB10949D7DD2"),
    );
    try test_encryption(
        &fromhex(16, "00000000000000000000000000000000"),
        &fromhex(16, "20000000000000000000000000000000"),
        &fromhex(16, "8F773194B78EF2B2740237EF12D08608"),
    );
    try test_encryption(
        &fromhex(16, "00000000000000000000000000000000"),
        &fromhex(16, "10000000000000000000000000000000"),
        &fromhex(16, "8B1EA69EE8D7C8D95B1DE4A670EC6997"),
    );
    // TODO: ...
}

test "NESSIE Serpent-128 test vector set 3" {
    try test_encryption(
        &fromhex(16, "00000000000000000000000000000000"),
        &fromhex(16, "00000000000000000000000000000000"),
        &fromhex(16, "3620B17AE6A993D09618B8768266BAE9"),
    );
    try test_encryption(
        &fromhex(16, "01010101010101010101010101010101"),
        &fromhex(16, "01010101010101010101010101010101"),
        &fromhex(16, "5107E36DBE81D9996D1EF7F3656FFC63"),
    );
    try test_encryption(
        &fromhex(16, "02020202020202020202020202020202"),
        &fromhex(16, "02020202020202020202020202020202"),
        &fromhex(16, "1AE5355487F88F824B6462B45C4C6AA5"),
    );
    try test_encryption(
        &fromhex(16, "03030303030303030303030303030303"),
        &fromhex(16, "03030303030303030303030303030303"),
        &fromhex(16, "1F830AF7D2A1B18F7A011C6FD0EEE8FB"),
    );
    // TODO: ...
}

// Helpers

fn test_encryption(key: *const [16]u8, plain: *const [16]u8, cipher: *const [16]u8) !void {
    var output: [16]u8 = undefined;

    const key_schedule = try serpent.expand_key(key);
    serpent.encrypt_block(plain, &output, &key_schedule);

    try testing.expectEqualSlices(u8, cipher, &output);
}

// This monstrosity is only temporary...
fn fromhex(L: comptime_int, comptime s: *const [2 * L]u8) [L]u8 {
    var result: [L]u8 = undefined;
    inline for (0..L) |i| {
        result[i] = (if (s[2 * i] >= '0' and s[2 * i] <= '9')
            s[2 * i] - '0'
        else if (s[2 * i] >= 'a' and s[2 * i] <= 'f')
            s[2 * i] - 'a' + 10
        else if (s[2 * i] >= 'A' and s[2 * i] <= 'F')
            s[2 * i] - 'A' + 10
        else
            @compileError("Invalid hex string.")) * 16 + (if (s[2 * i + 1] >= '0' and s[2 * i + 1] <= '9')
            s[2 * i + 1] - '0'
        else if (s[2 * i + 1] >= 'a' and s[2 * i + 1] <= 'f')
            s[2 * i + 1] - 'a' + 10
        else if (s[2 * i + 1] >= 'A' and s[2 * i + 1] <= 'F')
            s[2 * i + 1] - 'A' + 10
        else
            @compileError("Invalid hex string."));
    }
    return result;
}
