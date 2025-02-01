const std = @import("std");

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
