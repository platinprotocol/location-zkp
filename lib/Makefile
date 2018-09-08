CFLAGS = -g2 -O3 -fPIC -pthread -pipe 
CRYPTOPP = /Users/vfedyukovych/platin/src
CFLAGS += -I$(CRYPTOPP)
LIBS = -L$(CRYPTOPP)/cryptopp -L. -lproofs -lcryptopp

CFLAGS += -I../include

LIB= libproofs.so
SRCS= round.cpp qt.cpp gi.cpp
OBJS= $(SRCS:.cpp=.o)

all:	$(LIB)

test:	test-ggcd

test-ggcd:	test-ggcd.o

test-ggcd.o:	test-ggcd.cpp

$(LIB):	$(OBJS)
	g++ -shared $^ -o $@ $(LIBS)

.cpp.o:
	g++ -o $@ $(CFLAGS) -c $<

.o:
	g++ -o $@ $? $(LIBS)

clean:
	rm -rf $(OBJS) $(LIB)
