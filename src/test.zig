comptime {
    _ = .{
        @import("./primitive/blockcipher/aes.zig"),
        @import("./primitive/blockcipher/des.zig"),
        @import("./primitive/digest/sha_1.zig"),
        @import("./primitive/digest/sha_2.zig"),
        @import("./primitive/streamcipher/chacha20.zig"),
        @import("./primitive/streamcipher/salsa20.zig"),
    };
}

test {
    @import("std").testing.refAllDecls(@This());
}
