CFLAGS = -g2 -O3 -fPIC -pthread -pipe 
CRYPTOPP = /Users/vfedyukovych/platin/src
CFLAGS += -I$(CRYPTOPP)
LIBS = -L$(CRYPTOPP)/cryptopp -lcryptopp

CFLAGS += -I../include

LIB= libproofs.so
SRCS= round.cpp qt.cpp gi.cpp commitments.cpp parameters.cpp niproof.cpp lagrange.cpp geocoord.cpp
OBJS= $(SRCS:.cpp=.o)

all:	$(LIB)

test:	test-niproof test-ggcd test-qgcrd

test-niproof:	test-niproof.o $(LIB)

test-niproof.o:	test-niproof.cpp

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
