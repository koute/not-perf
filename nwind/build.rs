#[cfg(feature = "local-unwinding")]
extern crate cc;

#[cfg(feature = "local-unwinding")]
fn build() {
    use std::env;

    let source = match env::var( "TARGET" ).expect( "missing TARGET environment variable which should always be exported by cargo" ).as_str() {
        "x86_64-unknown-linux-gnu" => "src/arch/amd64_get_regs.s",
        "mips64-unknown-linux-gnuabi64" => "src/arch/mips64_get_regs.s",
        "armv7-unknown-linux-gnueabihf" => "src/arch/arm_get_regs.s",
        target => panic!( "unsupported target: {}", target )
    };

    let mut build = cc::Build::new();
    build.file( source );
    build.file( "src/arch/shadow_stack.c" );
    build.compile( "get_regs.a" );
}

#[cfg(not(feature = "local-unwinding"))]
fn build() {
}

fn main() {
    build();
}
