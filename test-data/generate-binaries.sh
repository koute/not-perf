#!/bin/bash

unset LD_PRELOAD
set -euo pipefail

TOOLCHAIN_INITIALIZED=0
function initialize_toolchain {
    if [[ "$TOOLCHAIN_INITIALIZED" = "1" ]]; then
        return
    fi

    TOOLCHAIN_INITIALIZED=1

    set +e
    if [[ "${OECORE_TARGET_SYSROOT-}" = "" ]]; then
        echo "No SDK detected!"
        print_sdk_urls_and_exit
    fi
    set -e

    BASENAME=`basename $OECORE_TARGET_SYSROOT`

    if [[ "$BASENAME" = "qemumips64" ]]; then
        PREFIX=mips64
        TARGET=mips64-unknown-linux-gnuabi64
        EXTRA_RUSTFLAGS="-C target-feature=-soft-float"
    elif [[ "$BASENAME" = "beaglebone" ]]; then
        PREFIX=arm
        TARGET=armv7-unknown-linux-musleabihf
        EXTRA_RUSTFLAGS="-C target-cpu=cortex-a8 -C target-feature=+neon,+armv7-a"
    elif [[ "$BASENAME" = "qemux86-64" ]]; then
        PREFIX=amd64
        TARGET=x86_64-unknown-linux-musl
        EXTRA_RUSTFLAGS=""
    elif [[ "$BASENAME" = "qemuarm64" ]]; then
        PREFIX=aarch64
        TARGET=aarch64-unknown-linux-gnu
        EXTRA_RUSTFLAGS=""
    else
        echo "Unknown SDK detected! ($BASENAME)"
        print_sdk_urls_and_exit
    fi

    echo "Detected SDK: $PREFIX $OECORE_SDK_VERSION"

    if [[ "$OECORE_SDK_VERSION" != "2.4.1" ]]; then
        echo "Wrong SDK version detected! (expected 2.4.1, got $OECORE_SDK_VERSION)"
        print_sdk_urls_and_exit
    fi
}

function compile {
    local NAME=$1
    local OUTPUT=$2
    shift
    shift
    local ARGS="$*"

    if [[ ! -e bin/$PREFIX-$OUTPUT ]]; then
        echo "Compiling $OUTPUT..."
        $CC src/$NAME.c -o bin/$PREFIX-$OUTPUT -g0 -O2 -fomit-frame-pointer -fasynchronous-unwind-tables -flto $ARGS
    fi
}

function print_sdk_urls_and_exit {
    echo ""
    echo "You can download an SDK from these URLs:"
    echo "  MIPS64 - http://downloads.yoctoproject.org/releases/yocto/yocto-2.4.1/toolchain/x86_64/poky-glibc-x86_64-core-image-minimal-mips64-toolchain-ext-2.4.1.sh"
    echo "     ARM - http://downloads.yoctoproject.org/releases/yocto/yocto-2.4.1/toolchain/x86_64/poky-glibc-x86_64-core-image-minimal-cortexa8hf-neon-toolchain-ext-2.4.1.sh"
    echo "   AMD64 - http://downloads.yoctoproject.org/releases/yocto/yocto-2.4.1/toolchain/x86_64/poky-glibc-x86_64-core-image-minimal-core2-64-toolchain-ext-2.4.1.sh"
    echo " AArch64 - http://downloads.yoctoproject.org/releases/yocto/yocto-2.4.1/toolchain/x86_64/poky-glibc-x86_64-core-image-minimal-aarch64-toolchain-ext-2.4.1.sh"
    exit 1
}

initialize_toolchain

compile usleep_in_a_loop    usleep_in_a_loop_no_fp
compile usleep_in_a_loop    usleep_in_a_loop_fp     -fno-omit-frame-pointer
compile pthread_cond_wait   pthread_cond_wait       -pthread
compile inline_functions    inline_functions        -ggdb3
compile noreturn            noreturn

if [ ! -e "bin/$PREFIX-usleep_in_a_loop_external_info" ]; then
    compile usleep_in_a_loop    usleep_in_a_loop_external_info  -fvisibility=hidden

    $OBJCOPY --only-keep-debug bin/$PREFIX-usleep_in_a_loop_external_info   bin/$PREFIX-usleep_in_a_loop_external_info.debug
    $STRIP --strip-debug --strip-unneeded bin/$PREFIX-usleep_in_a_loop_external_info
    $OBJCOPY --add-gnu-debuglink=bin/$PREFIX-usleep_in_a_loop_external_info.debug   bin/$PREFIX-usleep_in_a_loop_external_info
fi

export RUSTFLAGS="-C linker=${CC%% *} -C link-arg=--sysroot=$OECORE_TARGET_SYSROOT $EXTRA_RUSTFLAGS"
export CARGO_INCREMENTAL=0

cargo build --release --target=$TARGET
cp ../target/$TARGET/release/nperf bin/$PREFIX-nperf
