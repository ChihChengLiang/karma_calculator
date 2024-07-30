load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
load("//transpiler/rust:fhe_rs.bzl", "fhe_rust_library")
load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_library", "rust_test")

licenses(["notice"])

fhe_rust_library(
    name = "karma_rs_fhe_lib",
    lut_size = 0,
    src = "karma.cc",
    hdrs = ["karma.h"],
)

rust_library(
    name = "karma_rs_lib",
    srcs = ["karma_rs_lib.rs"],
    deps = [
        ":karma_rs_fhe_lib",
        "@crate_index//:phantom-zone",
    ],
)

rust_binary(
    name = "karma_rs_main",
    srcs = ["karma_rs_lib.rs"],
    deps = [
        ":karma_rs_fhe_lib",
        "@crate_index//:phantom-zone",
    ],
)

exports_files(
    [
        "karma.h",
        "karma.cc",
    ],
)
