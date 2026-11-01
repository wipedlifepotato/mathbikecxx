#!/bin/ksh
git submodule update --init --recursive
make -C i2psam
make Trie CXX="clang++ -I/usr/local/include -L/usr/local/lib"


