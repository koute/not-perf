#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

export RUST_BACKTRACE=1

cd nwind
cargo test --features local-unwinding --verbose
cargo check --no-default-features --verbose
cargo check --no-default-features --features logging --verbose
cd ..
cargo test -p perf_event_open --verbose
cargo test -p proc-maps --verbose
cargo test -p nperf --verbose
rustup target add mips64-unknown-linux-gnuabi64
rustup target add armv7-unknown-linux-gnueabihf
cargo check --target=mips64-unknown-linux-gnuabi64
cargo check --target=armv7-unknown-linux-gnueabihf
