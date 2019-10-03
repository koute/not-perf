#[cfg(feature = "local-unwinding")]
extern crate cc;

#[cfg(feature = "local-unwinding")]
fn build() {
    use std::env;

    let arch = match env::var( "TARGET" ).expect( "missing TARGET environment variable which should always be exported by cargo" ).as_str() {
        "x86_64-unknown-linux-gnu" => "amd64",
        "mips64-unknown-linux-gnuabi64" => "mips64",
        "armv7-unknown-linux-gnueabihf" => "arm",
        "aarch64-unknown-linux-gnu" => "aarch64",
        target => panic!( "unsupported target: {}", target )
    };

    let get_regs_s = format!( "src/arch/{}_get_regs.s", arch );
    let trampoline_s = format!( "src/arch/{}_trampoline.s", arch );

    println!( "cargo:rerun-if-changed={}", get_regs_s );
    println!( "cargo:rerun-if-changed={}", trampoline_s );

    let mut build = cc::Build::new();
    build.file( get_regs_s );
    build.file( trampoline_s );
    build.compile( "get_regs.a" );

    println!( "cargo:rustc-link-lib=stdc++" );
}

#[cfg(not(feature = "local-unwinding"))]
fn build() {
}

fn main() {
    build();
}
