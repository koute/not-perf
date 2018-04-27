[![Build Status](https://api.travis-ci.org/nokia/nperf.svg)](https://travis-ci.org/nokia/nperf)

# A sampling CPU profiler for Linux

`nperf` is a sampling CPU profiler for Linux similar to `perf`.

## Features

   * Support for AMD64, ARM and MIPS64 architectures (where MIPS64 requires a tiny out-of-tree patch to the kernel to work)
   * Support for offline and online stack trace unwinding
   * Support for profiling of binaries without any debug info (without the `.debug_frame` section)
      * using `.eh_frame` based unwinding (this is how normal C++ exception handling unwinds the stack)
        without requiring `.eh_frame_hdr` (which, depending on the compiler, may not be emitted)
      * using `.ARM.exidx` + `.ARM.extab` based unwinding (which is ARM specific and is used instead of `.eh_frame`)
   * Support for cross-architectural data analysis
   * Fully architecture-agnostic data format

## Why should I use this instead of `perf`?

If `perf` already works for you - great! Keep on using it.

This project was born out of a few limitations of the original `perf`
which make it non-ideal for CPU profiling in embedded-ish environments.
Some of those are as follows:
   * lack of support for MIPS64,
   * the big size of generated CPU profiling data due to offline-only stack unwinding,
     so if you only have a limited amount of storage space you either need to
     profile with a very low frequency, or for a very short amount of time;
   * lack of support for cross-architectural analysis - if you run `perf record`
     on ARM then you also need to run `perf report` either on ARM or under QEMU,
     and running the analysis under QEMU (depending on how you've compiled your binaries
     and with what flags you've launched `perf`) can take hours;
   * and poor support for profiling binaries which have limited or no debug info,
     which is often the case in big, embedded-lite projects where the debug info
     can't even fit on the target machine, or is not readily available.

## Building

1. Install at least Rust 1.26 (currently this means that you need to use Rust nightly).
2. Build it:

        $ cargo build --release

3. Grab the binary from `target/release/nperf`.

### Cross-compiling

1. Configure the linker for your target architecture in your `~/.cargo/config`, e.g.:

```
[target.mips64-unknown-linux-gnuabi64]
linker = "/path/to/your/sdk/mips64-octeon2-linux-gnu-gcc"
rustflags = [
  "-C", "link-arg=--sysroot=/path/to/your/sdk/sys-root/mips64-octeon2-linux-gnu"
]

[target.armv7-unknown-linux-gnueabihf]
linker = "/path/to/your/sdk/arm-cortexa15-linux-gnueabihf-gcc"
rustflags = [
  "-C", "link-arg=--sysroot=/path/to/your/sdk/sys-root/arm-cortexa15-linux-gnueabihf"
]
```

2. Compile, either for ARM or for MIPS64:

        $ cargo build --release --target=mips64-unknown-linux-gnuabi64
        $ cargo build --release --target=armv7-unknown-linux-gnueabihf

3. Grab the binary from `target/mips64-unknown-linux-gnuabi64/nperf` or `target/armv7-unknown-linux-gnueabihf/nperf`.

## Basic usage

Profiling an already running process by its PID:

    $ nperf record -p $PID_OF_YOUR_PROCESS -o datafile

Profiling a process by its name and waiting if it isn't running yet:

    $ nperf record -P cpu-hungry-program -w -o datafile

Generating a CPU flame graph from the gathered data:

    $ nperf collate datafile | flamegraph.pl > flame.svg

(Using [Brendan Gregg's flamegraph.pl](https://github.com/brendangregg/FlameGraph/blob/master/flamegraph.pl).)

## License

Licensed under either of

  * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
  * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
