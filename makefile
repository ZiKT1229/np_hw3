all: read.c
	gcc -g -o read read.c -lpcap

clean: 
	$(RM) read