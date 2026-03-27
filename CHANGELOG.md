## [unreleased]

### 🚀 Features

- Configuring Makefile and .gitignore
- Parsing cli args correctly
- Adding DNS resolution
- Adding func that parses which port will be scanned
- Adding func definitions for scanner.c file
- *(scanner)* Adding implementation of funcs to create raw socket and func to get src ip of interface
- *(scanner)* Adding implementation of funcs to calculate TCP header checksum for syn
- *(scanner)* Adding implementation of func that sends syn packet
- *(sniffer)* Adding implementation of sniffer funcs to parse response
- *(scanner)* Adding functional implementation of scanning tcp ports func (tested)
- *(main)* Adding func calls for tcp ports scanner function (and it works)
- *(sniffer)* Handling debug prints with verbose flag for clarity
- *(ipv6)* Adding implementation of tcp ipv6 scanning and fixing function for getting local ip address
- *(scanner)* Adding implementation of ipv4 and ipv6 udp scan functions
- *(sniffer)* Adding filtering for ICMP messages in sniffer function
- *(scanner)* Adding implementation of main scanning udp ports function
- *(udp)* Adding complete implementation for udp scanner
- *(Makefile)* Adding test target
- *(tests)* Adding test_scanner.sh for testing my implementation

### 🐛 Bug Fixes

- *(scanner)* Adding macros for POSIX
- *(scanner)* Moving POSIX defines into Makefile to make it global
- *(sniffer)* Missing timeout param in sniff_response func and fixing debug prints
- *(.gitignore)* Editing .gitignore to ignore some conf files
- *(main)* Fixing possible memory leaks when invalid inputs are passed to the program and better validation for cli args
- *(main)* Fixing seg fault when argument -i is not provided
- *(main)* Fixing double free cause free in wrong func scope
- *(main)* Replacing exit functions for a returns for better testing

### 💼 Other

- Project setup

### Possible future features

- Adding more verbose output for better user experience
- Adding more tests for better coverage
- Adding multithreading for faster scanning
