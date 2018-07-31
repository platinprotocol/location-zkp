CFLAGS = -g2 -O3 -fPIC -pthread -pipe 
CRYPTOPP = ..
CFLAGS += -I$(CRYPTOPP)
LIBS = -L$(CRYPTOPP)/cryptopp  -lcryptopp -lcurses

all:	clean demoCircle run

demoCircle:	demoCircle.o

demoCircle.o:	demoCircle.cpp

.cpp.o:
	g++ -o $@ $(CFLAGS) -c $<

.o:
	g++ -o $@ $? $(LIBS)

clean:
	rm -rf ./demoCircle ./demoCircle.o

run:
	./demoCircle
