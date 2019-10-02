#!/bin/bash

set -euo pipefail

CXX=x86_64-linux-gnu-g++ ./generate.sh
mv trampoline-template.s trampoline-template_amd64.s

CXX=mips64-linux-gnuabi64-g++ ./generate.sh
mv trampoline-template.s trampoline-template_mips64.s

CXX=aarch64-linux-gnu-g++ ./generate.sh
mv trampoline-template.s trampoline-template_aarch64.s

CXX=arm-linux-gnueabihf-g++ ./generate.sh
mv trampoline-template.s trampoline-template_arm.s
