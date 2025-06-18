CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -Isrc
LDFLAGS = 

# Source files
SRCDIR = src
SOURCES = $(SRCDIR)/chacha20.c $(SRCDIR)/poly1305.c $(SRCDIR)/common.c $(SRCDIR)/aead.c
HEADERS = $(SRCDIR)/chacha20.h $(SRCDIR)/poly1305.h $(SRCDIR)/common.h $(SRCDIR)/aead.h

# Directories
TESTDIR = test

# Targets
TARGETS = $(TESTDIR)/test_chacha20 $(TESTDIR)/test_poly1305 $(TESTDIR)/test_aead vault

.PHONY: all clean test

all: $(TARGETS)

# Build test programs
$(TESTDIR)/test_chacha20: $(TESTDIR)/test_chacha20.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(TESTDIR)/test_chacha20.c $(SOURCES)

$(TESTDIR)/test_poly1305: $(TESTDIR)/test_poly1305.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(TESTDIR)/test_poly1305.c $(SOURCES)

$(TESTDIR)/test_aead: $(TESTDIR)/test_aead.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(TESTDIR)/test_aead.c $(SOURCES)

# Build vault encryption tool
vault: vault.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ vault.c $(SOURCES)

# Clean build artifacts
clean:
	rm -f $(TARGETS)

# Run tests
test: $(TESTDIR)/test_chacha20 $(TESTDIR)/test_poly1305 $(TESTDIR)/test_aead
	./$(TESTDIR)/test_chacha20
	./$(TESTDIR)/test_poly1305
	./$(TESTDIR)/test_aead

# Install (optional, copies to /usr/local)
install: all
	install -d /usr/local/include
	install -m 644 $(SRCDIR)/chacha20.h /usr/local/include/
	install -m 644 $(SRCDIR)/poly1305.h /usr/local/include/
	install -d /usr/local/lib
	$(CC) $(CFLAGS) -c $(SOURCES)
	ar rcs libchacha20.a *.o
	rm -f *.o
	install -m 644 libchacha20.a /usr/local/lib/

# Create static library
libchacha20.a: $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -c $(SOURCES)
	ar rcs $@ *.o
	rm -f *.o
