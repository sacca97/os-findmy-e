fn main() {
    // libunicorn uses 16-byte atomics; on glibc Linux they come from libatomic.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        println!("cargo:rustc-link-lib=atomic");
    }
}
