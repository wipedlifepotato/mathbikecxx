Test:
	g++ *.cpp -lgmp -lgmpxx -o test
lTrigande: trigande.cpp trigande.h
	g++ trigande.cpp -c -fpic -o trigande.o
	g++ -shared -o libtrigande.so trigande.o -lgmpxx -lgmp
