TARGET = ipk-L4-scan

LOGIN = xlostap00

CC = gcc
CFLAGS = -Wall -Wextra -Werror -pedantic -g -std=c11 -D_GNU_SOURCE -D_DEFAULT_SOURCE -D_BSD_SOURCE
LDFLAGS = -lpcap

# Find all .c files
SRCS = $(wildcard src/*.c)

all: $(TARGET)
$(TARGET): $(SRCS) 
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	chmod +x $@

# For evaluation
NixDevShellName:
	@echo -n "c"

# My testing environment
NIX_ENV = nix develop --refresh "git+https://git.fit.vutbr.cz/NESFIT/dev-envs.git\#c" --command

# Local compilation with NIX
nix-build:
	$(NIX_ENV) make

test:
	make
	./tests/test_scanner.sh

# Archive
zip: clean
	zip -r $(LOGIN).zip src tests Makefile README.md LICENSE CHANGELOG.md

clean:
	rm -f $(TARGET) $(LOGIN).zip

.PHONY: all clean NixDevShellName nix-build nix-run nix-clean run zip test