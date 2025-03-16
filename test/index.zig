comptime {
    _ = .{
        @import("./primitive/blockcipher/aes.zig"),
        //@import("./primitive/blockcipher/des.zig"),
        @import("./primitive/blockcipher/serpent.zig"),
        //@import("./primitive/blockcipher/operation_modes.zig"),
        @import("./primitive/digest/sha.zig"),
        @import("./primitive/streamcipher/chacha20.zig"),
        @import("./primitive/streamcipher/salsa20.zig"),
    };
}

test {
    @import("std").testing.refAllDecls(@This());
}
