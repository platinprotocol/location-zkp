CFLAGS = -g2 -O3 -fPIC -pthread -pipe 
CRYPTOPP = ..
CFLAGS += -I$(CRYPTOPP)
LIBS = -L$(CRYPTOPP)/cryptopp  -lcryptopp -lcurses

all:	clean demo run

demo:	demo.o

demo.o:	demo.cpp

.cpp.o:
	g++ -o $@ $(CFLAGS) -c $<

.o:
	g++ -o $@ $? $(LIBS)

clean:
	rm -rf ./demo ./demo.o

run:
	./demo
