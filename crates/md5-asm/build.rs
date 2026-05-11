//! Build script for `md5-asm`.
//!
//! Compiles the C++ shim that wraps the vendored
//! [`animetosho/md5-optimisation`](https://github.com/animetosho/md5-optimisation)
//! block-compressor headers into a static library and exposes
//! `extern "C"` entry points for the Rust crate to link against.

fn main() {
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    let mut build = cc::Build::new();
    build
        .cpp(true)
        .file("src/wrapper.cpp")
        .include("vendor")
        .std("c++17")
        // The vendored inline-asm functions are marked
        // `always_inline`; -O3 matches the upstream benchmark
        // configuration the published numbers were measured at.
        .opt_level(3)
        .warnings(false);

    // Per-arch tuning. We don't try to be clever here — `cc` already
    // forwards the host's RUSTFLAGS-derived target. We only add what
    // the vendored headers genuinely need.
    assert!(
        matches!(arch.as_str(), "x86" | "x86_64" | "aarch64"),
        "md5-asm: unsupported target arch `{arch}` (need x86, x86_64, or aarch64)"
    );

    build.compile("md5_asm_shim");

    // Optional AVX512 single-buffer compressor. Compiled into its
    // own static lib so the `-mavx512*` flags don't contaminate
    // the base wrapper (which must run on any x86_64). The
    // entry points perform no CPUID gating themselves — the
    // caller (or the safe Rust wrapper) must check
    // `is_x86_feature_detected!("avx512vl")` first.
    let avx512 = std::env::var_os("CARGO_FEATURE_AVX512").is_some();
    if avx512 && arch == "x86_64" {
        let mut avx = cc::Build::new();
        avx.cpp(true)
            .file("src/wrapper_avx512.cpp")
            .include("vendor")
            .std("c++17")
            .opt_level(3)
            .warnings(false)
            .flag_if_supported("-mavx512f")
            .flag_if_supported("-mavx512vl")
            .flag_if_supported("-mavx512bw")
            .flag_if_supported("-mavx512dq");
        avx.compile("md5_asm_shim_avx512");
        println!("cargo:rerun-if-changed=src/wrapper_avx512.cpp");
    }

    println!("cargo:rerun-if-changed=src/wrapper.cpp");
    println!("cargo:rerun-if-changed=vendor/md5-x86-asm.h");
    println!("cargo:rerun-if-changed=vendor/md5-arm64-asm.h");
}
