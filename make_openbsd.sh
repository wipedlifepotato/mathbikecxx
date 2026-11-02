#!/bin/ksh
# The project Makefile uses GNU make conditionals, so use gmake on OpenBSD
# (pkg_add gmake).
if [ ! -f i2psam/i2psam.cpp ] && command -v git >/dev/null 2>&1; then
	git submodule update --init --recursive
fi
gmake -C i2psam
gmake Trie CXX="clang++ -I/usr/local/include -L/usr/local/lib"
