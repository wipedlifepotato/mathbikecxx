LIBS=-lgmp -lgmpxx
CXXFLAGS=-std=c++17 -pthread -Wall -Wextra
INCLUDES=-I. -Isrc
CXX ?= g++

# Platform specific libraries / defines.  These are GNU make constructs, so
# OpenBSD needs gmake (see make_openbsd.sh and the CI jobs).
UNAME_S := $(shell uname -s)
ifneq (,$(findstring MINGW,$(UNAME_S)))
	PLATFORM_LIBS=-lbcrypt -lws2_32
	PLATFORM_DEFS=-DWIN32
else ifneq (,$(findstring MSYS,$(UNAME_S)))
	PLATFORM_LIBS=-lbcrypt -lws2_32
	PLATFORM_DEFS=-DWIN32
else ifeq ($(OS),Windows_NT)
	PLATFORM_LIBS=-lbcrypt -lws2_32
	PLATFORM_DEFS=-DWIN32
else ifeq ($(UNAME_S),Darwin)
	PLATFORM_LIBS=-lsandbox
	PLATFORM_DEFS=
else
	PLATFORM_LIBS=
	PLATFORM_DEFS=
endif

# i2psam must see the same WIN32 define as the code that includes its headers.
SAM_CXXFLAGS=-Werror -Wall -Wextra -Wno-unused-parameter -std=c++11 -g $(PLATFORM_DEFS)

TRI_SRC=tri.cpp \
	src/config.cpp \
	src/common/util.cpp \
	src/common/platform.cpp \
	src/common/hash.cpp \
	src/common/crypto.cpp \
	src/common/frame.cpp \
	src/common/handshake.cpp \
	src/client/peer.cpp \
	src/client/client.cpp \
	src/server/relay.cpp \
	src/security/sandbox.cpp

all:
	printf "make Test # compile a test binary\r\n\r\n"
	printf "make lTrigande # compile a libtrigande.so\r\n\r\n"
	printf "make lHofman # compile a libhofman.so\r\n\r\n"
	printf "make Trie # compile TriMessage client and relay\r\n\r\n"
prepareSAM: 
	$(MAKE) -C i2psam CXX="$(CXX)" CXXFLAGS="$(SAM_CXXFLAGS)"
lHofman: alberthofman.cpp alberthofman.h
	$(CXX) alberthofman.cpp -c -fpic -o alberthofman.o
	$(CXX) -shared -o libhofman.so alberthofman.o $(LIBS)
Test: prepareSAM
	$(CXX) $(CXXFLAGS) $(PLATFORM_DEFS) $(INCLUDES) trigande.cpp test.cpp alberthofman.cpp $(LIBS) -li2psam -Li2psam $(PLATFORM_LIBS) -o test
lTrigande: trigande.cpp trigande.h
	$(CXX) trigande.cpp -c -fpic -o trigande.o
	$(CXX) -shared -o libtrigande.so trigande.o $(LIBS)
Trie: prepareSAM $(TRI_SRC) trigande.cpp alberthofman.cpp ChaCha20.cpp
	$(CXX) $(CXXFLAGS) $(PLATFORM_DEFS) $(INCLUDES) trigande.cpp $(TRI_SRC) alberthofman.cpp ChaCha20.cpp $(LIBS) -li2psam -Li2psam $(PLATFORM_LIBS) -o Trie
clean:
	rm -f Trie test *.o libtrigande.so libhofman.so
	$(MAKE) -C i2psam clean

.PHONY: all prepareSAM lHofman Test lTrigande Trie clean
