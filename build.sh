#!/bin/sh
rm -f *.bin
nasm -f bin -o pow.bin pow.nasm
ndisasm -b64 pow.bin