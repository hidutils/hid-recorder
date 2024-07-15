use std::env;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/hidrecord.bpf.c";

fn main() {
    let mut out = PathBuf::from(
        env::var_os("OUT_DIR").expect("expected OUT_DIR to be set by cargo but it's empty"),
    );
    out.push("hidrecord.skel.rs");

    SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(out)
        .expect("bpf compilation failed");
    println!("cargo:rerun-if-changed={}", SRC);
}
