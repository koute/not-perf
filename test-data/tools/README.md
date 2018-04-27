# How to compile MIPS64 kernel

    $ source /path/to/yocto/mips64-sdk/environment-setup-mips64-poky-linux
    $ wget http://git.yoctoproject.org/cgit/cgit.cgi/linux-yocto-4.12/snapshot/linux-yocto-4.12-09bddd16543c2f4fa1bb5a535994975dd1457fe2.tar.bz2
    $ tar -xf linux-yocto-4.12-09bddd16543c2f4fa1bb5a535994975dd1457fe2.tar.bz2
    $ cd linux-yocto-4.12-09bddd16543c2f4fa1bb5a535994975dd1457fe2
    $ patch -p1 < ../linux-mips-perf-event-open.patch
    $ cp ../linux-config-mips64 .config
    $ unset LDFLAGS
    $ make -j 4 vmlinux
    $ cat vmlinux | gzip > ../vmlinux-mips64.gz
