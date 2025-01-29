const std = @import("std");
const testing = std.testing;

const CryptoError = error{
    InvalidBufferSize,
};

// rn just for build, later will be used by high-level API
pub const aes = @import("primitive/blockcipher/aes.zig");
pub const chacha20 = @import("primitive/streamcipher/chacha20.zig");
pub const salsa20 = @import("primitive/streamcipher/salsa20.zig");
pub const sha = @import("primitive/digest/sha.zig");

// Leave this for later, maybe make a separate ffi module

//export fn aes_128_encrypt_block_ffi(block_in: [*c]const u8, len_in: usize, block_out: [*c]u8, len_out: usize) !void {
//    if (len_in != AES_128_BLOCK_SIZE or len_out != AES_128_BLOCK_SIZE)
//        return CryptoError.InvalidBufferSize;
//
//    aes_128_encrypt_block(block_in[0..AES_128_BLOCK_SIZE], block_out[0..AES_128_BLOCK_SIZE]);
//}
