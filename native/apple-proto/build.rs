//! Compiles the `.proto` files with prost. `protoc` is not assumed to be installed; the vendored
//! binary from `protoc-bin-vendored` is used (the same approach the Android crate uses for clang).

use std::path::PathBuf;

fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");
    std::env::set_var("PROTOC", protoc);

    let proto_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("proto");
    let protos = ["cloudkit.proto", "cuttlefish.proto"];
    let files: Vec<PathBuf> = protos.iter().map(|p| proto_dir.join(p)).collect();

    for f in &files {
        println!("cargo:rerun-if-changed={}", f.display());
    }

    let mut config = prost_build::Config::new();
    config
        .compile_protos(&files, &[proto_dir])
        .expect("compile protobuf definitions");
}
