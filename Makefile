LIBS=-lgmp -lgmpxx
all:
	printf "make Test # compile a test binary\r\n\r\n"
	printf "make lTrigande # compile a libtrigande.so\r\n\r\n"
	printf "make lHofman # compile a libhofman.so\r\n\r\n"
prepareSAM: 
	make -C i2psam
lHofman: alberthofman.cpp alberthofman.h
	g++ alberthofman.cpp -c -fpic -o alberthofman.o
	g++ -shared -o libhofman.so alberthofman.o $(LIBS)
Test: prepareSAM
	g++ trigande.cpp test.cpp alberthofman.cpp $(LIBS) -li2psam -Li2psam -o test
lTrigande: trigande.cpp trigande.h
	g++ trigande.cpp -c -fpic -o trigande.o
	g++ -shared -o libtrigande.so trigande.o $(LIBS)
