use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/hidrecord.bpf.c";
const SRC_TRACING: &str = "src/bpf/hidrecord_tracing.bpf.c";

fn main() {
    let out = PathBuf::from("src/bpf/hidrecord.skel.rs");
    let out_tracing = PathBuf::from("src/bpf/hidrecord_tracing.skel.rs");

    if let Err(e) = SkeletonBuilder::new().source(SRC).build_and_generate(out) {
        println!("cargo:warning=Failed to build BPF sources: {:?}. Using provided BPF compilation outputs instead.", e.source().unwrap());
        println!("cargo:rustc-env=SKELFILE=bpf/hidrecord.default.skel.rs");
        println!("cargo:rustc-env=SKELFILE_TRACING=bpf/hidrecord_tracing.default.skel.rs");
        return;
    }
    println!("cargo:rerun-if-changed={}", SRC);
    SkeletonBuilder::new()
        .source(SRC_TRACING)
        .build_and_generate(out_tracing)
        .expect("bpf compilation failed");
    println!("cargo:rerun-if-changed={}", SRC_TRACING);
    println!("cargo:rerun-if-changed=src/bpf/hidrecord.h");
    println!("cargo:rustc-env=SKELFILE=bpf/hidrecord.skel.rs");
    println!("cargo:rustc-env=SKELFILE_TRACING=bpf/hidrecord_tracing.skel.rs");
}
