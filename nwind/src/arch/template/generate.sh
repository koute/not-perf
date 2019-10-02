#!/bin/sh

CXX=${CXX:-g++}

$CXX -O3 -s trampoline-template.cpp -fvisibility=hidden -S
sed -i "s/\t/    /g" trampoline-template.s
