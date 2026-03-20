TARGET = ipk-L4-scan

LOGIN = xlostap00

CC = gcc
CFLAGS = -Wall -Wextra -Werror -pedantic -g -std=c11

# Find all .c files
SRCS = $(wildcard src/*.c)

all: $(TARGET)
$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^
	chmod +x $@

# For evaluation
NixDevShellName:
	@echo -n "c"

# My testing environment
NIX_ENV = nix develop --refresh "git+https://git.fit.vutbr.cz/NESFIT/dev-envs.git\#c" --command

# Local compilation with NIX
nix-build:
	$(NIX_ENV) make all

# Local testing with NIX
nix-run:
	$(NIX_ENV) make run

run: $(TARGET)
	./$(TARGET)

nix-clean:
	$(NIX_ENV) make clean

# Archive
zip: clean
	zip -r $(TARGET).zip src Makefile README.md LICENSE CHANGELOG.md

clean:
	rm -f $(TARGET) $(LOGIN).zip

.PHONY: all clean NixDevShellName nix-build nix-run nix-clean run zip