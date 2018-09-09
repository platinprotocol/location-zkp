CFLAGS = -g2 -O3 -fPIC -pthread -pipe 
CRYPTOPP = /Users/vfedyukovych/platin/src
CFLAGS += -I$(CRYPTOPP)
LIBS = -L$(CRYPTOPP)/cryptopp -lcryptopp

CFLAGS += -I../include

LIB= libproofs.so
SRCS= round.cpp qt.cpp gi.cpp
OBJS= $(SRCS:.cpp=.o)

all:	$(LIB)

test:	test-ggcd test-qgcrd

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
