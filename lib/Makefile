CFLAGS = -g2 -O0 -fPIC -pthread -pipe
CRYPTOPP = /Users/vfedyukovych/platin/src
CFLAGS += -I$(CRYPTOPP)
LIBS = -L$(CRYPTOPP)/cryptopp -lcryptopp

CFLAGS += -I../include

LIB= libproofs.so
SRCS= round.cpp qt.cpp gi.cpp commitments.cpp parameters.cpp niproof.cpp lagrange.cpp geocoord.cpp
SRCS+= eulerid.cpp
OBJS= $(SRCS:.cpp=.o)

all:	$(LIB)

test:	test-niproof test-ggcd test-qgcrd

test-niproof:	test-niproof.o $(LIB)

test-niproof.o:	test-niproof.cpp


test-eulerid.o:	test-eulerid.cpp

test-eulerid:	test-eulerid.o

primes_decomposition.inc:	test-eulerid
	./test-eulerid > primes_decomposition.inc

lagrange.o:	lagrange.cpp primes_decomposition.inc

test-ggcd:	test-ggcd.o $(LIB)

test-ggcd.o:	test-ggcd.cpp

test-qgcrd:	test-qgcrd.o $(LIB)

test-qgcrd.o:	test-qgcrd.cpp

$(LIB):	$(OBJS)
	g++ -shared $^ -o $@ $(LIBS)

.cpp.o:
	g++ -o $@ $(CFLAGS) -c $<

.o:
	g++ -o $@ $<  -L. -lproofs $(LIBS)

clean:
	rm -rf $(OBJS) $(LIB)
	rm -rf ./cli_ni_verify
	rm -rf ./cli_ni_verify.o
	rm -rf ./cli_ni_proof
	rm -rf ./cli_ni_proof.o
	rm -rf ./cli_ni_proof.o

cli_ni:	cli_ni_proof cli_ni_verify

cli_ni_proof:	cli_ni_proof.o $(LIB)

cli_ni_proof.o:	cli_ni_proof.cpp

cli_ni_verify:	cli_ni_verify.o $(LIB)

cli_ni_verify.o:	cli_ni_verify.cpp
