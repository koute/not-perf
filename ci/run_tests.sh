#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

export RUST_BACKTRACE=1

cd nwind
cargo test --features local-unwinding --verbose
cargo test --features local-unwinding --release --verbose
cargo build --verbose
cargo test --verbose
cargo check --no-default-features --verbose
cargo check --no-default-features --features "log" --verbose
cargo check --no-default-features --features "log debug-logs" --verbose
cd ..

cd perf_event_open
cargo test --verbose
cd ..

cd proc-maps
cargo test --verbose
cd ..

cargo test --verbose

cd cli
cargo build --verbose
cd ..

cargo check --no-default-features --verbose
rustup target add mips64-unknown-linux-gnuabi64
rustup target add armv7-unknown-linux-gnueabihf
rustup target add aarch64-unknown-linux-gnu
cargo check --target=mips64-unknown-linux-gnuabi64
cargo check --target=armv7-unknown-linux-gnueabihf
cargo check --target=aarch64-unknown-linux-gnu
