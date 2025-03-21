const std = @import("std");
const testing = std.testing;

const blockcipher = @import("primitive").blockcipher;
const hex_to_bytes = @import("utility").byte_operations.hex_to_bytes;

// Use AES to test all of the operation modes.
const aes = blockcipher.aes;

// ----------------------------------- CBC MODE ----------------------------------- //

const cbc = blockcipher.operation_mode.cbc;

test "AES-128-CBC basic test" {
    const BS = aes.BLOCK_SIZE;
    const KS = aes.KEY_SIZE_128;
    const ENC = aes.aes128_encrypt_block;
    const DEC = aes.aes128_decrypt_block;

    // Plaintext source: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)
    // Retrieved 2025/02/01
    const key = [KS]u8{ 0x0c, 0x49, 0x08, 0x75, 0xd4, 0x63, 0x2c, 0x2a, 0x9a, 0x73, 0xab, 0xb6, 0x5c, 0x67, 0x06, 0x0d };
    const iv = [BS]u8{ 0xbe, 0x10, 0x47, 0x59, 0xac, 0xf3, 0x9c, 0x10, 0x1e, 0x2e, 0x37, 0x77, 0x85, 0xe0, 0x13, 0x0e };
    const plaintext = "Ehrsam, Meyer, Smith and Tuchman invented the cipher block chaining (CBC) mode of operation in 1976.[23] In CBC mode, each block of plaintext is XORed with the previous ciphertext block before being encrypted. This way, each ciphertext block depends on all plaintext blocks processed up to that point. To make each message unique, an initialization vector must be used in the first block.";
    const ciphertext = [_]u8{ 0x1c, 0x15, 0x02, 0xb8, 0x88, 0xfe, 0xf2, 0x23, 0x72, 0xbf, 0x14, 0x7a, 0xf7, 0x11, 0xde, 0x5a, 0x53, 0x7b, 0x3e, 0xf3, 0xe3, 0xea, 0xb7, 0xd8, 0xe2, 0x4d, 0x9a, 0x82, 0xd8, 0x84, 0x96, 0xc2, 0xa4, 0x8a, 0x82, 0xd5, 0xe9, 0x46, 0x3d, 0x4e, 0xf2, 0xc2, 0xcc, 0x62, 0x73, 0x9d, 0x6e, 0xf8, 0x86, 0xd0, 0xac, 0xb0, 0x0a, 0x80, 0xef, 0x3a, 0x83, 0x74, 0xb7, 0xf9, 0x4f, 0xc5, 0x52, 0x2c, 0x5c, 0x52, 0xd8, 0x41, 0xd4, 0x0b, 0xc2, 0xa9, 0xa6, 0xa3, 0x7b, 0xcc, 0x2e, 0x15, 0xd5, 0xc9, 0x8e, 0x6a, 0x0b, 0x50, 0xe2, 0xbf, 0xcb, 0x09, 0x61, 0x1b, 0x26, 0x78, 0x1a, 0x23, 0xe7, 0xd5, 0x0c, 0x50, 0x3f, 0xc8, 0xa9, 0xb4, 0xea, 0x97, 0xa1, 0xaf, 0xf4, 0xcd, 0xb4, 0x76, 0x0e, 0x4c, 0xa9, 0xfc, 0xf8, 0xbd, 0x45, 0xbb, 0x7b, 0xd3, 0x84, 0x52, 0xac, 0x29, 0xa3, 0xee, 0x62, 0x23, 0xc1, 0x6a, 0xca, 0x1c, 0x62, 0x0a, 0x8b, 0xce, 0x36, 0x9e, 0x7e, 0xb5, 0x5b, 0x2a, 0xa8, 0x85, 0x37, 0x51, 0x0c, 0xed, 0x05, 0xca, 0xb6, 0xc6, 0xd9, 0xc0, 0x0d, 0x9d, 0x57, 0x2a, 0xcd, 0x79, 0xf6, 0x23, 0x36, 0x6d, 0x50, 0x29, 0xff, 0xa2, 0x71, 0x5a, 0x77, 0x0e, 0x26, 0x41, 0x2f, 0x22, 0xc6, 0x8f, 0xdf, 0x2a, 0x0f, 0xb6, 0x19, 0xb7, 0xdb, 0x6b, 0x62, 0x04, 0x50, 0x97, 0x13, 0x8d, 0x60, 0xfa, 0x31, 0x89, 0x36, 0x9e, 0x46, 0xf9, 0x51, 0xcc, 0xd0, 0x90, 0x8b, 0x3d, 0x7a, 0x67, 0xfa, 0x16, 0xdf, 0x3a, 0xe8, 0x96, 0x9c, 0xac, 0x18, 0x7a, 0x12, 0x55, 0x52, 0xcf, 0xc0, 0xeb, 0x0b, 0x49, 0xc2, 0xda, 0x1a, 0x20, 0xaa, 0xee, 0x04, 0x14, 0xa5, 0x23, 0xbf, 0x60, 0x95, 0x09, 0x19, 0x55, 0xa4, 0x93, 0xfe, 0xab, 0x33, 0x6d, 0x4f, 0x51, 0xcb, 0xff, 0xe5, 0x69, 0x39, 0x4c, 0x1a, 0x8c, 0xf9, 0x12, 0x0d, 0x67, 0x7c, 0x10, 0xe9, 0xf7, 0xdf, 0xa6, 0x92, 0x4f, 0x6c, 0x55, 0xca, 0x42, 0xa2, 0x7b, 0xd1, 0xbf, 0x3b, 0xcf, 0xc1, 0xda, 0xad, 0x80, 0x12, 0x95, 0xe7, 0x86, 0x4a, 0x04, 0x1f, 0x01, 0x9e, 0x64, 0xaf, 0x02, 0xcd, 0xb3, 0x84, 0x39, 0x42, 0x8b, 0x04, 0x04, 0x5d, 0x76, 0x20, 0x49, 0x3b, 0x87, 0x03, 0x31, 0xa5, 0x40, 0x4d, 0xca, 0x0e, 0x15, 0x28, 0x03, 0x77, 0xbc, 0xe4, 0x70, 0x69, 0x0d, 0x21, 0x80, 0xa7, 0x92, 0xf7, 0xe0, 0x74, 0x4d, 0xe7, 0xf0, 0x26, 0x55, 0xe7, 0x14, 0xb7, 0xde, 0xa0, 0xf5, 0xd3, 0xe7, 0xea, 0x2b, 0x0b, 0x28, 0x7c, 0xd5, 0x36, 0x0f, 0xb0, 0x83, 0x42, 0x0d, 0x1d, 0xf5, 0xc9, 0xcc, 0xe2, 0x68, 0x16, 0xa1, 0xcc, 0xcb, 0x09, 0x2c, 0x85, 0xdf, 0xec, 0x02, 0xf5, 0x5f, 0x67, 0x6d, 0x04, 0xae, 0x3a, 0x34, 0xa8, 0x46, 0x9d, 0x80, 0xd8, 0xee, 0xfb, 0x12, 0x9f, 0x25, 0xd5, 0x0b, 0x38, 0xfe, 0x99, 0x59, 0xeb, 0xb9 };

    // Test encryption.
    {
        const ct_length = comptime cbc.get_padded_buffer_length(BS, plaintext);
        var ct_buffer: [ct_length]u8 = undefined;

        var ctx = cbc.cbc_pkcs7_encrypt_new(BS, KS, ENC, &key, &iv);
        defer cbc.cbc_pkcs7_encrypt_destroy(BS, KS, ENC, &ctx);

        var pt_processed_bytes: usize = 0;
        while (plaintext.len - pt_processed_bytes >= aes.BLOCK_SIZE) : (pt_processed_bytes += aes.BLOCK_SIZE)
            cbc.cbc_pkcs7_encrypt_block(
                BS,
                KS,
                ENC,
                &ctx,
                @ptrCast(plaintext[pt_processed_bytes .. pt_processed_bytes + aes.BLOCK_SIZE]),
                @ptrCast(ct_buffer[pt_processed_bytes .. pt_processed_bytes + aes.BLOCK_SIZE]),
            );

        try cbc.cbc_pkcs7_encrypt_final(BS, KS, ENC, &ctx, plaintext[pt_processed_bytes..], @ptrCast(ct_buffer[pt_processed_bytes..]));

        try testing.expectEqualSlices(u8, ciphertext[0..], ct_buffer[0..]);
    }

    // Test decryption.
    {
        var pt_buffer: [ciphertext.len]u8 = undefined;

        var ctx = cbc.cbc_pkcs7_decrypt_new(BS, KS, DEC, &key, &iv);
        defer cbc.cbc_pkcs7_decrypt_destroy(BS, KS, DEC, &ctx);

        var ct_processed_bytes: usize = 0;
        while (ciphertext.len - ct_processed_bytes >= 2 * aes.BLOCK_SIZE) : (ct_processed_bytes += aes.BLOCK_SIZE)
            cbc.cbc_pkcs7_decrypt_block(
                BS,
                KS,
                DEC,
                &ctx,
                @ptrCast(ciphertext[ct_processed_bytes .. ct_processed_bytes + aes.BLOCK_SIZE]),
                @ptrCast(pt_buffer[ct_processed_bytes .. ct_processed_bytes + aes.BLOCK_SIZE]),
            );

        const residue_length = try cbc.cbc_pkcs7_decrypt_final(
            BS,
            KS,
            DEC,
            &ctx,
            ciphertext[ct_processed_bytes..],
            pt_buffer[ct_processed_bytes..],
        );

        try testing.expectEqual(plaintext.len % aes.BLOCK_SIZE, residue_length);
        try testing.expectEqualSlices(u8, plaintext[0..], pt_buffer[0..plaintext.len]);
    }
}

// ----------------------------------- GCM MODE ----------------------------------- //

const gcm = @import("primitive").blockcipher.operation_mode.gcm;

// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
test "AES-GCM Test Case 1" {
    const K = hex_to_bytes(128 / 8, "00000000000000000000000000000000");
    const P = hex_to_bytes(0, "");
    const IV = hex_to_bytes(96 / 8, "000000000000000000000000");

    const H = hex_to_bytes(128 / 8, "66e94bd4ef8a2c3b884cfa59ca342b2e");
    const Y0 = hex_to_bytes(128 / 8, "00000000000000000000000000000001");
    // E_K_Y0      = 58e2fccefa7e3061367f1d57a4e7455a
    // len_A_len_C = 00000000000000000000000000000000
    // GHASH_H_A_C = 00000000000000000000000000000000
    const C = hex_to_bytes(0, "");
    const T = hex_to_bytes(128 / 8, "58e2fccefa7e3061367f1d57a4e7455a");

    var ctx = try gcm.gcm128_new(aes.KEY_SIZE_128, aes.aes128_encrypt_block, &K, &IV);
    try testing.expectEqualSlices(u8, &H, &ctx.h);
    try testing.expectEqualSlices(u8, &Y0, &ctx.counter);

    var ciphertext_buffer: @TypeOf(P) = undefined;
    try gcm.gcm128_encrypt(aes.KEY_SIZE_128, aes.aes128_encrypt_block, &ctx, &P, &ciphertext_buffer);
    try testing.expectEqualSlices(u8, &C, &ciphertext_buffer);

    var tag_buffer: @TypeOf(T) = undefined;
    try gcm.gcm128_encrypt_final(aes.KEY_SIZE_128, aes.aes128_encrypt_block, &ctx, &tag_buffer);
    try testing.expectEqualSlices(u8, &T, &tag_buffer);
}

test "AES-GCM Test Case 2" {
    const K = hex_to_bytes(128 / 8, "00000000000000000000000000000000");
    const P = hex_to_bytes(128 / 8, "00000000000000000000000000000000");
    const IV = hex_to_bytes(96 / 8, "000000000000000000000000");
    const H = hex_to_bytes(128 / 8, "66e94bd4ef8a2c3b884cfa59ca342b2e");
    const Y0 = hex_to_bytes(128 / 8, "00000000000000000000000000000001");
    // E_K_Y0      = 58e2fccefa7e3061367f1d57a4e7455a
    // Y1          = 00000000000000000000000000000002
    // E_K_Y1      = 0388dace60b6a392f328c2b971b2fe78
    // X1          = 5e2ec746917062882c85b0685353deb7
    // len_A_len_C = 00000000000000000000000000000080
    // GHASH_H_A_C = f38cbb1ad69223dcc3457ae5b6b0f885
    const C = hex_to_bytes(128 / 8, "0388dace60b6a392f328c2b971b2fe78");
    const T = hex_to_bytes(128 / 8, "ab6e47d42cec13bdf53a67b21257bddf");

    var ctx = try gcm.gcm128_new(aes.KEY_SIZE_128, aes.aes128_encrypt_block, &K, &IV);
    try testing.expectEqualSlices(u8, &H, &ctx.h);
    try testing.expectEqualSlices(u8, &Y0, &ctx.counter);

    var ciphertext_buffer: @TypeOf(P) = undefined;
    try gcm.gcm128_encrypt(aes.KEY_SIZE_128, aes.aes128_encrypt_block, &ctx, &P, &ciphertext_buffer);
    try testing.expectEqualSlices(u8, &C, &ciphertext_buffer);

    var tag_buffer: @TypeOf(T) = undefined;
    try gcm.gcm128_encrypt_final(aes.KEY_SIZE_128, aes.aes128_encrypt_block, &ctx, &tag_buffer);
    try testing.expectEqualSlices(u8, &T, &tag_buffer);
}
