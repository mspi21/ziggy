// ----------------------------------- ERROR DEFINITIONS -----------------------------------  //

pub const MessageLengthLimitExceeded = error.MessageLengthLimitExceeded;

// ----------------------------------- GENERIC SHA ALGORITHMS ----------------------------------- //

pub fn generic_update(
    ShaCtx: type,
    limit_length_bits: comptime_int,
    compression_function: *const fn (*ShaCtx) void,
    ctx: *ShaCtx,
    message: []const u8,
) !void {
    if (ctx.message_length + message.len >= limit_length_bits / 8)
        return MessageLengthLimitExceeded;

    const cnt_buffered_bytes: usize = @intCast(ctx.message_length % ShaCtx.BLOCK_SIZE);

    // Simplest case - the message does not fully fill the block yet,
    // so it's just copied to the context buffer and no hashing is done.
    if (cnt_buffered_bytes + message.len < ShaCtx.BLOCK_SIZE) {
        @memcpy(
            ctx.message_buffer[cnt_buffered_bytes .. cnt_buffered_bytes + message.len],
            message[0..],
        );
        ctx.message_length += message.len;
        return;
    }

    // Otherwise: first, copy & hash the first block.
    @memcpy(
        ctx.message_buffer[cnt_buffered_bytes..],
        message[0 .. ShaCtx.BLOCK_SIZE - cnt_buffered_bytes],
    );
    compression_function(ctx);
    var cnt_message_bytes_processed = ShaCtx.BLOCK_SIZE - cnt_buffered_bytes;
    ctx.message_length += cnt_message_bytes_processed;

    // Then, as long as there is at least another block available, copy and hash it.
    while (message.len - cnt_message_bytes_processed >= ShaCtx.BLOCK_SIZE) {
        @memcpy(
            ctx.message_buffer[0..],
            message[cnt_message_bytes_processed .. cnt_message_bytes_processed + ShaCtx.BLOCK_SIZE],
        );
        compression_function(ctx);
        ctx.message_length += ShaCtx.BLOCK_SIZE;
        cnt_message_bytes_processed += ShaCtx.BLOCK_SIZE;
    }

    // Finally, copy any leftover bytes to the context buffer without hashing.
    const cnt_leftover_bytes = message.len - cnt_message_bytes_processed;
    @memcpy(
        ctx.message_buffer[0..cnt_leftover_bytes],
        message[cnt_message_bytes_processed..],
    );
    ctx.message_length += cnt_leftover_bytes;
}

pub fn generic_final(
    ShaCtx: type,
    WordType: type,
    MessageLengthIntType: type,
    digest_length: comptime_int,
    compression_function: *const fn (*ShaCtx) void,
    ctx: *ShaCtx,
    out: *[digest_length]u8,
) void {
    const message_length_bytes = @typeInfo(MessageLengthIntType).Int.bits / 8;
    const cnt_leftover_bytes: usize = @intCast(ctx.message_length % ShaCtx.BLOCK_SIZE);

    // Simple case: The leftover message is short enough* for the padding to only span one block.
    // *: "Short enough" depends on the particular SHA variant.
    if (cnt_leftover_bytes < ShaCtx.BLOCK_SIZE - message_length_bytes) {
        const cnt_padding_bytes = ShaCtx.BLOCK_SIZE - message_length_bytes - cnt_leftover_bytes;

        // The padding (without the message length) is a single 1 bit followed by 0 bits.
        ctx.message_buffer[cnt_leftover_bytes] = 0x80;
        @memset(ctx.message_buffer[cnt_leftover_bytes + 1 .. cnt_leftover_bytes + cnt_padding_bytes], 0x00);

        // The length is appended.
        const length = serialize_int_big_endian(MessageLengthIntType, ctx.message_length * 8);
        @memcpy(ctx.message_buffer[cnt_leftover_bytes + cnt_padding_bytes ..], length[0..]);

        // The padded block is finally hashed.
        compression_function(ctx);
    }
    // Otherwise, the padding spans 2 blocks in total
    // and two more hash iterations are performed.
    else {
        // Pad and hash the first block.
        ctx.message_buffer[cnt_leftover_bytes] = 0x80;
        @memset(ctx.message_buffer[cnt_leftover_bytes + 1 ..], 0x00);
        compression_function(ctx);

        // Hash the second block.
        @memset(ctx.message_buffer[0..(ShaCtx.BLOCK_SIZE - message_length_bytes)], 0x00);
        const length = serialize_int_big_endian(MessageLengthIntType, ctx.message_length * 8);
        @memcpy(ctx.message_buffer[(ShaCtx.BLOCK_SIZE - message_length_bytes)..], length[0..]);
        compression_function(ctx);
    }

    // Serialize the result.
    const word_size = @typeInfo(WordType).Int.bits / 8;
    var serialized_bytes: usize = 0;
    for (0..ctx.hash.len) |w| {
        const serialized_word = serialize_int_big_endian(WordType, ctx.hash[w]);

        // The digest_length does not have to be a multiple of word_size!
        if (serialized_bytes > digest_length - word_size) {
            @memcpy(out[w * word_size ..], serialized_word[0..(digest_length - serialized_bytes)]);
            serialized_bytes += word_size;
            break;
        } else {
            @memcpy(out[(w * word_size)..((w + 1) * word_size)], serialized_word[0..]);
            serialized_bytes += word_size;
        }
    }
}

// TODO: generic_destroy()

// ----------------------------------- LOGICAL FUNCTIONS ----------------------------------- //

pub fn ch(T: type, x: T, y: T, z: T) T {
    return (x & y) ^ (~x & z);
}

pub fn parity(T: type, x: T, y: T, z: T) T {
    return x ^ y ^ z;
}

pub fn maj(T: type, x: T, y: T, z: T) T {
    return (x & y) ^ (x & z) ^ (y & z);
}

// ----------------------------------- HELPERS ----------------------------------- //

pub fn rotl(T: type, word: T, bits: comptime_int) T {
    if (comptime bits >= @bitSizeOf(T))
        @compileError("Will not rotate word left by more bits than it has!");
    return (word << bits) | (word >> (@bitSizeOf(T) - bits));
}

pub fn rotr(T: type, word: T, bits: comptime_int) T {
    if (comptime bits >= @bitSizeOf(T))
        @compileError("Will not rotate word right by more bits than it has!");
    return rotl(T, word, @bitSizeOf(T) - bits);
}

pub fn shr(T: type, word: T, bits: comptime_int) T {
    return word >> bits;
}

pub fn serialize_int_big_endian(T: type, int: T) [@sizeOf(T)]u8 {
    var res: [@sizeOf(T)]u8 = undefined;
    for (0..@sizeOf(T)) |i|
        res[i] = @truncate(int >> @intCast(8 * (@sizeOf(T) - i - 1)));
    return res;
}

pub fn deserialize_int_big_endian(T: type, bytes: *const [@sizeOf(T)]u8) T {
    var res: T = 0;
    for (0..@sizeOf(T)) |i|
        res |= @as(T, bytes[i]) << @intCast(8 * (@sizeOf(T) - i - 1));
    return res;
}

// ----------------------------------- TEST HELPERS ----------------------------------- //

const testing = @import("std").testing;

pub fn hex_nibble_to_int(ascii_hex: u8) u4 {
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

pub fn run_hash_precomputed_tests(
    Ctx: type,
    L: comptime_int,
    fn_new: *const fn () Ctx,
    fn_update: *const fn (*Ctx, []const u8) anyerror!void,
    fn_final: *const fn (*Ctx, *[L]u8) void,
    tests: []const struct { message: []const u8, hash: *const [2 * L]u8 },
) !void {
    var digest_buffer: [L]u8 = undefined;

    for (tests) |t| {
        var ctx = fn_new();
        try fn_update(&ctx, t.message);
        fn_final(&ctx, &digest_buffer);

        const reference = hex_to_bytes(L, t.hash);
        try testing.expectEqualSlices(u8, reference[0..], digest_buffer[0..]);
    }
}
