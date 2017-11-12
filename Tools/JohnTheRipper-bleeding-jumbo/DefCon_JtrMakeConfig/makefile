CC=g++
XFLAG =-Wall -ansi -pedantic
CFLAG =
main: jtrMakeConfig 


jtrMakeConfig: jtrMakeConfig.o 
	$(CC) $(CFLAG) jtrMakeConfig.o -o jtrMakeConfig
	
jtrMakeConfig.o: jtrMakeConfig.c
	$(CC) $(CFLAG) -c jtrMakeConfig.c

clean:
	rm -f jtrMakeConfig
	rm -f *.o
