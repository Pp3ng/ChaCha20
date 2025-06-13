CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -g -Isrc
LDFLAGS = 

# Source files
SRCDIR = src
SOURCES = $(SRCDIR)/chacha20.c
HEADERS = $(SRCDIR)/chacha20.h
OBJECTS = $(SOURCES:.c=.o)

# Targets
TARGETS = test_chacha20 example cc20crypt

.PHONY: all clean test

all: $(TARGETS)

# Build test program
test_chacha20: test_chacha20.o $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^

# Build example program
example: example.o $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^

# Build file encryption tool
cc20crypt: cc20crypt.o $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^

# Object files
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

# Run tests
test: test_chacha20
	./test_chacha20

# Clean build artifacts
clean:
	rm -f $(OBJECTS) test_chacha20.o example.o cc20crypt.o $(TARGETS)

# Install (optional, copies to /usr/local)
install: all
	install -d /usr/local/include
	install -m 644 $(SRCDIR)/chacha20.h /usr/local/include/
	install -d /usr/local/lib
	ar rcs libchacha20.a $(OBJECTS)
	install -m 644 libchacha20.a /usr/local/lib/

# Create static library
libchacha20.a: $(OBJECTS)
	ar rcs $@ $^
