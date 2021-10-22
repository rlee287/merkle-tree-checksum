fn main() {
    let version_obj = rustc_version::version().unwrap();
    println!("cargo:rustc-env=RUSTC_VERSION_STR={}", version_obj);
}
