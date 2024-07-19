use std::env;
use std::path::{Path, PathBuf};

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/hidrecord.bpf.c";
const SRC_TRACING: &str = "src/bpf/hidrecord_tracing.bpf.c";

// from https://stackoverflow.com/questions/37498864/finding-executable-in-path-with-rust
fn which<P>(exe_name: P) -> Option<PathBuf>
where
    P: AsRef<Path>,
{
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths)
            .filter_map(|dir| {
                let full_path = dir.join(&exe_name);
                if full_path.is_file() {
                    Some(full_path)
                } else {
                    None
                }
            })
            .next()
    })
}

fn main() {
    if which("clang").is_none() {
        println!(
            "cargo:warning='clang' executable not found, using provided bpf compilation outputs"
        );
        println!("cargo:warning= changes in 'src/bpf/*' will not be taken into account");
        return;
    }

    let out = PathBuf::from("src/bpf/hidrecord.skel.rs");
    let out_tracing = PathBuf::from("src/bpf/hidrecord_tracing.skel.rs");

    SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(out)
        .expect("bpf compilation failed");
    println!("cargo:rerun-if-changed={}", SRC);
    SkeletonBuilder::new()
        .source(SRC_TRACING)
        .build_and_generate(out_tracing)
        .expect("bpf compilation failed");
    println!("cargo:rerun-if-changed={}", SRC_TRACING);
    println!("cargo:rerun-if-changed=src/bpf/hidrecord.h");
}
