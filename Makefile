all: fsm

CFLAGS = -g -Wall

fsm : fsm.o

clean: 
	rm -f fsm
