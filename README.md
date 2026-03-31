# IPK L4 Scanner

## 1. Project Overview

The IPK L4 Scanner is a command-line network exploration tool designed to perform transport-layer (Layer 4) port scanning. It utilizes raw sockets to craft and send custom TCP and UDP packets and uses the `libpcap` library to sniff and analyze the network responses. The scanner determines whether specified ports are `open`, `closed`, or `filtered` for TCP protocols and `open`, `closed` for UDP protocols based on the responses received. The tool supports both IPv4 and IPv6 addresses, automatically resolves domain names and handles various port specification formats such as single ports, comma-separated lists, and ranges.

## 2. Implemented Features

* **TCP SYN Scanning:** Performs TCP half-open scans that means, we don't use full 3-way hanshake for scanning (sends SYN, expects SYN-ACK for `open`, RST for `closed`).
* **UDP Scanning:** Sends empty UDP datagrams (expects ICMP messages for `closed`, no response for `open`).
* **IPv4 & IPv6 Support:** Program handles both IP versions using protocol-independent structures (`getaddrinfo`).
* **DNS Resolution:** Automatically resolves domain names to IP addresses (both A and AAAA records) before scanning.
* **Complex Port Parsing:** Supports single ports, comma-separated lists (e.g., `80,443`), ranges (e.g., `1-100`), and their combinations.
* **Robust Error Handling:** Validates all CLI inputs (invalid interfaces, out-of-bounds ports, invalid IPs) and any error retuns error code 1 with a brief message to `stderr`.

## 3. Build and Run Instructions

### Prerequisites

* GCC or Clang compiler
* Make
* `libpcap` development headers (`libpcap-dev`)

### Building the Project

To compile the project, run the following command in the root directory:

```bash
make
```

This will generate the `ipk-L4-scan` executable.

### Running the Scanner

Since the application uses raw sockets and packet sniffing, it **requires root (`sudo`) privileges**.

**Usage:**

```bash
sudo ./ipk-L4-scan -i <interface> -t <tcp_ports> -u <udp_ports> [-w <timeout>] <host>
Options:
  -h|--help        Show this help message and exit
  -i <interface>   Network interface to use (e.g., eth0, lo, tun0)
  -t <tcp_ports>   TCP ports to scan (e.g., 22,80,100-200)
  -u <udp_ports>   UDP ports to scan (e.g., 53,67,100-200)
  -w <timeout>     Timeout in milliseconds for waiting for responses (default: 1000ms)
  <host>           Target hostname or IP address to scan
```

Output will be printed to `stdout` in the format `<IP_ADDRESS> <PORT> <PROTOCOL> <STATE>` for each scanned port.

**Example:**

```bash
sudo ./ipk-L4-scan -i eth0 -t 22,80,443 -u 53,67 -w 2000 scanme.nmap.org
```

Expected output:

```text
2600:3c01::f03c:91ff:fe18:bb2f 22 tcp open
2600:3c01::f03c:91ff:fe18:bb2f 80 tcp open
2600:3c01::f03c:91ff:fe18:bb2f 443 tcp closed
2600:3c01::f03c:91ff:fe18:bb2f 53 udp closed
2600:3c01::f03c:91ff:fe18:bb2f 67 udp closed
45.33.32.156 22 tcp open
45.33.32.156 80 tcp open
45.33.32.156 443 tcp closed
45.33.32.156 53 udp closed
45.33.32.156 67 udp open
```

## 4. Design Decisions

* **Project decomposition:** The architecture is split into `main.c` (CLI parsing and program flow), `scanner.c` (packet crafting and checksum calculations), and `sniffer.c` (libpcap response capturing).
* **Sequential Scanning:** To ensure reliability and avoid packet drops or problems with complex thread synchronization with `libpcap`, the tool scans ports sequentially. While slower for large ranges, it guarantees deterministic results and simplifies timeout handling.
* **getaddrinfo over inet_pton:** `getaddrinfo` was chosen for address resolution because it naturally handles DNS lookups, IPv4/IPv6 dual-stack resolution, and returns a linked list of addresses to scan, avoiding hardcoded address family checks in the main loop.
* **Zero-exit on Network Unreachable:** If a route is missing (e.g., sending an IPv6 packet over an IPv4-only interface), the `sendto()` function fails with `EHOSTUNREACH`. Instead of treating this as a fatal error, the program simply reports the port as `closed` and continues scanning other ports, providing more comprehensive results rather than halting on a single misconfiguration.
* **Checksum Calculation:** The checksum is calculated using a standard algorithm that includes the pseudo-header for TCP/UDP packets, ensuring that crafted packets are valid and accepted by the target host.
* **Libpcap library for Sniffing:** Using `libpcap` allows for efficient packet capture and filtering directly in user space, enabling the program to listen for specific responses without needing to rely on raw socket reception, which can be more complex and less portable.

## 5. Testing

Testing was done manually during development using Wireshark to inspect the crafted packets and their responses. However, a comprehensive automated test suite was also developed to validate both the internal logic and the end-to-end functionality of the scanner.

### 5.1 Testing Environment

All automated and manual tests were executed in the following environment to ensure reproducibility:

* **OS:** NixOS / Ubuntu 22.04.4 LTS x86_64
* **Kernel:** Linux 6.17.0-19-generic
* **Compiler:** GCC 13.3.0
* **Network Topology:** Tests were primarily executed on the local loopback interface (`lo`) to isolate the scanner from external firewalls, preventing unpredictable network latency and packet drops.
* **Tools Used:** `nc` (Netcat) for mocking open TCP/UDP servers, `iptables` for simulating filtered ports, and the `Unity` C testing framework for unit tests. Wireshark was used for manual packet inspection during development.

### 5.2 Automated Test Execution

Some of the test cases were generated by LLMs (e.g., ChatGPT) to cover specific edge cases.
The project includes a comprehensive automated test suite consisting of **C Unit Tests** and **Bash Integration Tests**.

To execute the complete test suite, run:

```bash
make test
```

*Note: The integration tests will temporarily spawn local `nc` servers and use `sudo` to run the scanner against them.*

### 5.3 Comparison with a Comparable Tool (Nmap)

The scanner was compared against the industry-standard **Nmap** (`nmap -sS` for TCP and `nmap -sU` for UDP).

* **Behavior:** Both tools behave identically regarding the TCP SYN handshake. Sending a SYN to an open port yields a SYN-ACK, correctly parsed by both.
* **Differences:** Nmap implements complex dynamic timeout calculations and asynchronous multi-threading, whereas this scanner uses a fixed timeout and sequential scanning. Additionally, Nmap classifies silent UDP ports as `open|filtered`, whereas our program classify them as `open` for simplicity. Nmap also randomizes source ports and packet timings to evade intrusion detection systems, while this scanner uses a fixed source port (54321) for simplicity and predictability in testing.

### 5.4 Test Cases (Coverage)

#### Test Case 1: Validating Internal Logic (Unit Tests)

* **What was tested:** System functions (`if_nametoindex`, `inet_pton`), protocol numbers and TCP/IP checksum calculation algorithms. User function for getting the source IP address based on the selected interface was also tested.
* **Why it was tested:** To ensure foundational helper functions work flawlessly, accurately identifying invalid IP addresses and correctly calculating deterministic checksums before any packets are sent.
* **How it was tested:** Using the Unity testing framework directly calling the functions with edge-case inputs (e.g., out-of-bounds IP octets, odd-length byte arrays for checksums).
* **Inputs:** e.g., passing `999.999.999.999` into `inet_pton`.
* **Expected Output:** The framework expects the validation to fail (return `0`).
* **Actual Output:** The function correctly rejected the IP, and Unity reported `PASS`.

#### Test Case 2: TCP SYN Scan on Open/Closed Ports (Integration)

* **What was tested:** End-to-end functionality of sending a SYN packet and catching the appropriate response over the loopback interface.
* **Why it was tested:** To verify that raw socket crafting, routing, and `libpcap` filtering correctly interpret the TCP handshake.
* **How it was tested:** Local TCP servers were started in the background using Netcat (`nc -l -p 55001`). The scanner was executed against this port and another unused port.
* **Inputs:** `sudo ./ipk-L4-scan -i lo -t 55001,55010 127.0.0.1`
* **Expected Output:** Port 55001 should be reported as `open`, port 55010 should be reported as `closed`.
* **Actual Output:**

```text
  127.0.0.1 55001 tcp open
  127.0.0.1 55010 tcp closed
```

#### Test Case 3: CLI Edge Cases and Error Handling (Integration)

* **What was tested:** The program's ability to handle invalid user inputs without crashing or producing undefined behavior.
* **Why it was tested:** To ensure the scanner doesn't crash (e.g., Segmentation Fault) when fed garbage data, out-of-bounds ports, missing arguments, or invalid interfaces.
* **How it was tested:** Passing malformed arguments through the automated Bash script and verifying that the process exits with a non-zero exit code.
* **Inputs:** e.g., `./ipk-L4-scan -i lo -t 65535-65536 127.0.0.1` (port out of bounds).
* **Expected Output:** The program prints an error message to `stderr` and exits  with a non-zero status.
* **Actual Output:**

```text
  ERROR: Invalid port range.
```

  *(Program exited with code 1, test script reported PASS)*.

## 6. Known Limitations

* **Sequential Scanning Speed:** Because the tool scans one port at a time and waits for the timeout before proceeding to the next, scanning a large range of filtered or dropped ports (e.g., `1-65535`) takes a considerable amount of time.
* **Root Privileges:** The application strictly requires `root` access due to the underlying OS restrictions on creating `AF_PACKET` or `SOCK_RAW` sockets.

## 7. References

* **RFC 793:** Transmission Control Protocol (TCP packet structure and flags)
* **RFC 768:** User Datagram Protocol (UDP packet structure)
* **RFC 792 / RFC 4443:** Internet Control Message Protocol (ICMPv4 / ICMPv6 errors)
* **getaddrinfo documentation:** `man getaddrinfo` for address resolution and protocol-independent socket programming
* **Checksum algorithm logic:** [https://www.geeksforgeeks.org/computer-networks/calculation-of-tcp-checksum](https://www.geeksforgeeks.org/computer-networks/calculation-of-tcp-checksum/)
* **libpcap documentation:** `man pcap` and tcpdump filter syntax
* **Linux Raw Sockets:** `man 7 raw` and `man 7 packet` for socket programming details
* **Unity Test Framework:** ThrowTheSwitch Unity ([https://github.com/ThrowTheSwitch/Unity](https://github.com/ThrowTheSwitch/Unity)) for C unit testing
