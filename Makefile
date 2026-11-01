LIBS=-lgmp -lgmpxx
CXXFLAGS=-std=c++17 -pthread -Wall -Wextra
INCLUDES=-I. -Isrc
CXX=g++

TRI_SRC=tri.cpp \
	src/config.cpp \
	src/common/util.cpp \
	src/common/crypto.cpp \
	src/common/frame.cpp \
	src/common/handshake.cpp \
	src/client/peer.cpp \
	src/client/client.cpp \
	src/server/relay.cpp

all:
	printf "make Test # compile a test binary\r\n\r\n"
	printf "make lTrigande # compile a libtrigande.so\r\n\r\n"
	printf "make lHofman # compile a libhofman.so\r\n\r\n"
	printf "make Trie # compile TriMessage client and relay\r\n\r\n"
prepareSAM: 
	make -C i2psam
lHofman: alberthofman.cpp alberthofman.h
	$(CXX) alberthofman.cpp -c -fpic -o alberthofman.o
	$(CXX) -shared -o libhofman.so alberthofman.o $(LIBS)
Test: prepareSAM
	$(CXX) $(CXXFLAGS) $(INCLUDES) trigande.cpp test.cpp alberthofman.cpp $(LIBS) -li2psam -Li2psam -o test
lTrigande: trigande.cpp trigande.h
	$(CXX) trigande.cpp -c -fpic -o trigande.o
	$(CXX) -shared -o libtrigande.so trigande.o $(LIBS)
Trie: prepareSAM $(TRI_SRC) trigande.cpp alberthofman.cpp ChaCha20.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) trigande.cpp $(TRI_SRC) alberthofman.cpp ChaCha20.cpp $(LIBS) -li2psam -Li2psam -o Trie
clean:
	rm -f Trie test *.o libtrigande.so libhofman.so
	$(MAKE) -C i2psam clean

.PHONY: all prepareSAM lHofman Test lTrigande Trie clean
