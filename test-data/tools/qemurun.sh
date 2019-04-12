#!/bin/bash

set -euo pipefail

SELF_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

function syntax {
    echo ""
    echo "Syntax: qemurun.sh [-w workdir] <-a amd64|arm|arm64|mips64> <-o output-directory> [-i input ...] [script-to-run]"
    exit 1
}

if [[ "$#" == 0 ]]; then
    syntax
fi

ARCH=""
INPUT_DIR=""
OUTPUT_DIR=""
SCRIPT=""
WORKDIR="cache"
INPUTS=()

while [[ $# -gt 0 ]]
do
    KEY="$1"

    case $KEY in
        -a)
        ARCH="$2"
        shift
        shift
        ;;
        -i)
        INPUTS+=($(realpath "$2"))
        shift
        shift
        ;;
        -o)
        OUTPUT_DIR="$2"
        shift
        shift
        ;;
        -w)
        WORKDIR="$2"
        shift
        shift
        ;;
        *)
        SCRIPT="$1"
        shift
        ;;
    esac
done

if [[ "$ARCH" = "" ]]; then
    echo "Missing architecture!"
    syntax
fi

if [[ "$SCRIPT" != "" ]]; then
    if [ ! -e "$SCRIPT" ]; then
        echo "Specified script doesn't exist!"
        exit 1
    fi

    SCRIPT=$(realpath "$SCRIPT")
fi

QEMU_APPEND=""
DTB_URL=""
INITRD_URL=""
KERNEL_URL=""

if [[ "$ARCH" = "mips64" ]]; then
    QEMU=qemu-system-mips64
    YOCTO_MACHINE=qemumips64
    MACHINE=malta
    CPU=MIPS64R2-generic
    KERNEL_GZIP="$SELF_DIR/vmlinux-mips64.gz"
    KERNEL_FILENAME="vmlinux-mips64"
    KERNEL_APPEND="console=ttyS0"
    IO_DEVICE=virtio-blk-pci
elif [[ "$ARCH" = "arm" ]]; then
    QEMU=qemu-system-arm
    YOCTO_MACHINE=qemuarm
    MACHINE=vexpress-a15
    CPU=cortex-a15
    KERNEL_FILENAME=vmlinuz
    KERNEL_URL="http://ftp.debian.org/debian/dists/jessie/main/installer-armhf/current/images/netboot/vmlinuz"
    DTB_FILENAME="vexpress-v2p-ca15-tc1.dtb"
    DTB_URL="http://ftp.nl.debian.org/debian/dists/jessie/main/installer-armhf/current/images/device-tree/vexpress-v2p-ca15-tc1.dtb"
    INITRD_FILENAME="initrd.gz"
    INITRD_URL="http://ftp.debian.org/debian/dists/jessie/main/installer-armhf/current/images/netboot/initrd.gz"
    KERNEL_APPEND="console=ttyAMA0 earlycon"
    IO_DEVICE=virtio-blk-device
elif [[ "$ARCH" = "arm64" || "$ARCH" = "aarch64" ]]; then
    QEMU=qemu-system-aarch64
    YOCTO_MACHINE=qemuarm64
    MACHINE=virt
    CPU=cortex-a57
    KERNEL_FILENAME=Image
    KERNEL_URL="http://downloads.yoctoproject.org/releases/yocto/yocto-2.4.1/machines/qemu/qemuarm64/$KERNEL_FILENAME"
    KERNEL_APPEND="console=ttyAMA0,115200"
    IO_DEVICE=virtio-blk-device
elif [[ "$ARCH" = "amd64" ]]; then
    QEMU=qemu-system-x86_64
    YOCTO_MACHINE=qemux86-64
    MACHINE=pc
    CPU=core2duo
    KERNEL_FILENAME=bzImage-qemux86-64.bin
    KERNEL_URL="http://downloads.yoctoproject.org/releases/yocto/yocto-2.4.1/machines/qemu/qemux86-64/$KERNEL_FILENAME"
    KERNEL_APPEND="console=ttyS0"
    IO_DEVICE=virtio-blk-pci
else
    echo "Unknown architecture: '$1'"
    exit 1
fi

if [[ "$OUTPUT_DIR" != "" ]]; then
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_DIR=$(realpath "$OUTPUT_DIR")
fi

mkdir -p "$WORKDIR"
cd "$WORKDIR"

if [ ! -e "$KERNEL_FILENAME" ]; then
    if [[ "$KERNEL_URL" != "" ]]; then
        wget "$KERNEL_URL"
    elif [[ "$KERNEL_GZIP" != "" ]]; then
        cat "$KERNEL_GZIP" | gzip -d > "$KERNEL_FILENAME"
    fi
fi

if [ ! -e "core-image-minimal-$YOCTO_MACHINE.tar.bz2" ]; then
    wget http://downloads.yoctoproject.org/releases/yocto/yocto-2.4.1/machines/qemu/$YOCTO_MACHINE/core-image-minimal-$YOCTO_MACHINE.tar.bz2
fi

if [ ! -e "core-image-minimal-dev-$YOCTO_MACHINE.tar.bz2" ]; then
    wget http://downloads.yoctoproject.org/releases/yocto/yocto-2.4.1/machines/qemu/$YOCTO_MACHINE/core-image-minimal-dev-$YOCTO_MACHINE.tar.bz2
fi

if [[ "$DTB_URL" != "" ]]; then
    if [ ! -e "$DTB_FILENAME" ]; then
        wget "$DTB_URL"
    fi
    QEMU_APPEND="$QEMU_APPEND -dtb $DTB_FILENAME"
fi

if [[ "$INITRD_URL" != "" ]]; then
    if [ ! -e "$INITRD_FILENAME" ]; then
        wget "$INITRD_URL"
    fi

    if [ ! -e "initrd-root" ]; then
        mkdir initrd-root
        cat "$INITRD_FILENAME" | gzip -d | cpio --quiet -id -D initrd-root 2> /dev/null || true
    fi
fi

if [[ "$ARCH" = "mips64" ]]; then
    if [ ! -e "poky-glibc-x86_64-core-image-minimal-mips64-toolchain-ext-2.4.1.sh" ]; then
        wget http://downloads.yoctoproject.org/releases/yocto/yocto-2.4.1/toolchain/x86_64/poky-glibc-x86_64-core-image-minimal-mips64-toolchain-ext-2.4.1.sh
    fi

    if [ ! -e "sdk" ]; then
        chmod +x poky-glibc-x86_64-core-image-minimal-mips64-toolchain-ext-2.4.1.sh
        ./poky-glibc-x86_64-core-image-minimal-mips64-toolchain-ext-2.4.1.sh -nyd sdk
    fi

    if [ ! -e "sysroot-destdir" ]; then
        tar -xf sdk/sstate-cache/db/sstate:glibc:mips64-poky-linux:2.26:r0:mips64:3:dbe4fa3d0196885b55e250fd61fc5612_populate_sysroot.tgz
    fi
fi

rm -Rf root
mkdir root

tar -C root -xf core-image-minimal-$YOCTO_MACHINE.tar.bz2
tar -C root -xf core-image-minimal-dev-$YOCTO_MACHINE.tar.bz2 --wildcards '*libgcc_s.so*'

if [[ "$ARCH" = "mips64" ]]; then
    cp sysroot-destdir/lib/libc-2.26.so root/lib
    cp sysroot-destdir/lib/libdl-2.26.so root/lib
    cp sysroot-destdir/lib/librt-2.26.so root/lib
    cp sysroot-destdir/lib/libm-2.26.so root/lib
    cp sysroot-destdir/lib/libresolv-2.26.so root/lib
    cp sysroot-destdir/lib/libpthread-2.26.so root/lib
    cp sysroot-destdir/lib/ld-2.26.so root/lib
fi

ln -s ld-2.26.so root/lib/ld-linux-armhf.so.3
ln -s sbin/init root/init
if [[ "$INITRD_URL" != "" ]]; then
    cp -R initrd-root/lib/modules root/lib
fi
mkdir root/input root/output

if [[ "$SCRIPT" != "" ]]; then
    cp "$SCRIPT" root/user.sh
else
    echo "#!/bin/sh" > root/user.sh
    echo "exec /bin/sh" >> root/user.sh
fi

chmod +x root/user.sh

rm -f root/sbin/sulogin
echo "#!/bin/sh" > root/sbin/sulogin
cat << EOS >> root/sbin/sulogin
/user.sh

cd /output && tar -zcf - . > /dev/vda
EOS

chmod +x root/sbin/sulogin

rm -f root/bin/start_getty
echo "#!/bin/sh" > root/bin/start_getty
echo "/sbin/poweroff" >> root/bin/start_getty
chmod +x root/bin/start_getty

set +u
for INPUT in "${INPUTS[@]}"; do
    cp "$INPUT" "root/input/$(basename $INPUT)"
done
set -u

cd root
find . | cpio --quiet -H newc -o | gzip -1 > ../root.cpio.gz
cd ..

dd if=/dev/zero of=output.tgz bs=1M count=32 status=none

export QEMU_AUDIO_DRV=none
$QEMU -M $MACHINE -nographic -no-reboot \
    -kernel $KERNEL_FILENAME \
    -cpu $CPU \
    -m 256 \
    -vga none \
    -drive format=raw,file=output.tgz,id=disk0,if=none \
    -device $IO_DEVICE,drive=disk0 \
    -append "panic=1 raid=noautodetect $KERNEL_APPEND root=/dev/ram0 single" \
    -initrd root.cpio.gz \
    $QEMU_APPEND

if [[ "$OUTPUT_DIR" != "" ]]; then
    OUTPUT_TGZ=$(realpath output.tgz)
    cd "$OUTPUT_DIR"
    tar -xf "$OUTPUT_TGZ"
fi
