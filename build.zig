const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const utility_module = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "src/utility//index.zig" },
    });
    const primitive_module = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "src/primitive/index.zig" },
    });
    primitive_module.addImport("utility", utility_module);

    const lib = b.addStaticLibrary(.{
        .name = "crypto",
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib.root_module.addImport("primitive", primitive_module);
    lib.root_module.addImport("utility", utility_module);

    b.installArtifact(lib);

    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("test/index.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_unit_tests.root_module.addImport("primitive", primitive_module);
    lib_unit_tests.root_module.addImport("utility", utility_module);

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
}
