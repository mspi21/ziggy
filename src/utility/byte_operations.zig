const std = @import("std");

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

pub fn hex_to_bytes(L: comptime_int, hex_string: *const [2 * L]u8) [L]u8 {
    var res: [L]u8 = undefined;
    for (0..L) |i| {
        res[i] = @as(u8, hex_nibble_to_int(hex_string[2 * i])) << 4;
        res[i] |= hex_nibble_to_int(hex_string[2 * i + 1]);
    }
    return res;
}

pub fn word_to_bytes_le(word: u32) [4]u8 {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, word, .little);
    return bytes;
}

pub fn bytes_to_word_le(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .little);
}

pub fn word_to_bytes_be(word: u32) [4]u8 {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, word, .big);
    return bytes;
}

pub fn bytes_to_word_be(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .big);
}
