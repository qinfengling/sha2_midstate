TARGET = midstate

SRCS = main.c sha2.c
OBJS = $(patsubst %.c,%.o,$(SRCS))

CFLAGS = -g -O0 -Wall

all: $(OBJS)
	gcc $(OBJS) -o $(TARGET)

sha2.o:sha2.c
	gcc -c $(CFLAGS) $< -o $@

main.o:main.c
	gcc -c $(CFLAGS) $< -o $@

clean:
	@rm -f $(OBJS) $(TARGET)
