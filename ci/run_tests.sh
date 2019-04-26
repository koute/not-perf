#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

export RUST_BACKTRACE=1

set +e
echo "$(rustc --version)" | grep -q "nightly"
if [ "$?" = "0" ]; then
    export IS_NIGHTLY=1
else
    export IS_NIGHTLY=0
fi
set -e

cd nwind
if [ "$IS_NIGHTLY" = "1" ]; then
    cargo test --features local-unwinding --verbose
    cargo test --features local-unwinding --release --verbose
fi
cargo build --verbose
cargo test --verbose
cargo check --no-default-features --verbose
cargo check --no-default-features --features "log" --verbose
cargo check --no-default-features --features "log debug-logs" --verbose
cd ..
cargo test -p perf_event_open --verbose
cargo test -p proc-maps --verbose
cargo build -p nperf --verbose
cargo test -p nperf --bin nperf --verbose
cargo check --no-default-features --verbose
rustup target add mips64-unknown-linux-gnuabi64
rustup target add armv7-unknown-linux-gnueabihf
rustup target add aarch64-unknown-linux-gnu
cargo check --target=mips64-unknown-linux-gnuabi64
cargo check --target=armv7-unknown-linux-gnueabihf
cargo check --target=aarch64-unknown-linux-gnu
