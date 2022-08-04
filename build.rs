// Jackson Coxson

fn main() {
    println!("cargo:rerun-if-changed=src/bindings.rs");
    // Run bindgen
    cbindgen::Builder::new()
        .with_crate(".")
        .generate()
        .unwrap()
        .write_to_file("secret_tunnel.h");
}
