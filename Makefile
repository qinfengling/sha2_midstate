all: sha2.o main.o
	gcc -g -O0 sha2.o main.o -o test

sha2.o:sha2.c
	gcc -c -g -O0 $< -o $@

main.o:main.c
	gcc -c -g -O0 $< -o $@

clean:
	rm *.o test
