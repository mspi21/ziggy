pub const aes = @import("aes.zig");
pub const des = @import("des.zig");

pub const operation_mode = struct {
    pub const gcm = @import("mode_gcm.zig");
};
