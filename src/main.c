/*
 * @file main.c
 * @author Patrik Lošťák <xlostap00>
 * @brief Entrypoint of simple program for L4 scanning
 */

#define _POSIX_C_SOURCE 200112L
#include "sniffer.h"
#include "scanner.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <net/if.h>
#include <signal.h>

// non-ANSI func declaration hidden by c11
extern char* strdup(const char*);

#define DEFAULT_TIMEOUT 1000 // ms
#define MAX_PORTS 65535 // max num of ports
#define SRC_PORT 54321 // random high number for source port
bool verbose_flag = false;
// Use boolean arr of ports to be scanned
// Port 65535 is on idx 65536 
bool scan_tcp[MAX_PORTS + 1] = {false}; 
bool scan_udp[MAX_PORTS + 1] = {false};

// Handler for SIGINT to exit corrctly
sig_atomic_t running = 1;
extern pcap_t *global_handle; // Defined in sniffer.c, shared with signal handler

void signal_handler(int sig) {
  (void)sig; // unused param, avoid warning
  running = 0; // Set flag to stop main loop
  if (global_handle != NULL) {
    pcap_breakloop(global_handle); // Break pcap loop if running 
  }
}

// Just print help message and exit program with 0
void print_help() {
  printf("Usage: ./ipk-L4-scan -v -i INTERFACE [-u PORTS] [-t PORTS] HOST [-w "
         "TIMEOUT] [-h | --help]\n");
  printf("Options:\n");
  printf("  -v                Enable verbose output for debugging\n");
  printf("  -i INTERFACE      Specify the network interface to use for scanning (required)\n"
  "                    Use -i alone to list all available interfaces\n");
  printf("  -t PORTS          Comma-separated list of TCP ports to scan (e.g., "
         "22,80,443) or ranges (e.g., 1-1024)\n");
  printf("  -u PORTS          Comma-separated list of UDP ports to scan (e.g., 53,123) or ranges (e.g., 1-1024)\n");
  printf("  -w TIMEOUT        Timeout in milliseconds to wait for a response before determining port status (default: 1000 ms)\n");
  printf("  -h, --help        Show this help message and exit\n");
  exit(0);
}

// Print all active network interfaces if only -i is typed
void show_interfaces() {
  struct ifaddrs *ifaddr, *ifa, *prev;
  if (getifaddrs(&ifaddr) == -1) {
    // getifaddrs sets errno on err
    perror("ERROR: getifaddrs");
    exit(1);
  }
  // Go through the list of ifs and print them to stdout seperated by nl
  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_name == NULL) {
      continue; // Just skip empty records
    }

    // Logic to avoid duplicits
    bool parsed = false;
    for (prev = ifaddr; prev != ifa; prev = prev->ifa_next) {
      if (prev->ifa_name != NULL && strcmp(prev->ifa_name, ifa->ifa_name) == 0) {
        parsed = true;
        break;
      }
    }

    if (!parsed) {
      // If not parsed we can print it
      printf("%s\n", ifa->ifa_name);
    }
  }
  // allocated dynamically so little cleaning
  freeifaddrs(ifaddr);
  exit(0);
}

// Func that parses ports from cli and set true/false to each port
void parse_ports(const char *port_str, bool *port_arr) {
  if (port_str == NULL) {
    return;
  }

  // copy of inputed port string cause of strtok modifies original one
  char *str_copy = strdup(port_str);
  if (!str_copy) {
    perror("ERROR: strdup failed");
    exit(1);
  }

  // parse ports seperated by , (22,23,24)
  char *token = strtok(str_copy, ",");
  while (token != NULL) {
    // Find dash for range (1-65536)
    char *dash = strchr(token, '-');

    if (dash != NULL) { // port range
      int start, end;
      if (sscanf(token, "%d-%d", &start, &end) == 2) {
        if (start >= 0 && end <= MAX_PORTS && start <= end) {
          for (int p_idx = start; p_idx <= end; p_idx++) {
            port_arr[p_idx] = true;
          }
        } else {
          fprintf(stderr, "ERROR: Invalid port range\n");
          free(str_copy);
          exit(1);
        }
      }
    } else { // one specific port
      // check for non-numeric chars in port number
      for (size_t i = 0; token[i] != '\0'; i++) {
        if (!isdigit(token[i])) {
          fprintf(stderr, "ERROR: Invalid port number format\n");
          free(str_copy);
          exit(1);
        }
      }
      int port = atoi(token);
      if (port >= 1 && port <= MAX_PORTS) {
        port_arr[port] = true;
      } else {
        fprintf(stderr, "ERROR: Invalid port\n");
        free(str_copy);
        exit(1);
      }
    }
    // Load another token after ,
    token = strtok(NULL, ",");
  }
  free(str_copy); // clean up the copy
}

void verbose_print(bool verbose_flag, const char *tcp_ports, const char *udp_ports, const char *interface, int timeout, const char *host) {
  if (verbose_flag) {
    fprintf(stderr, "--- Loaded values ---\n");
    fprintf(stderr, "Interface: %s\n", interface);
    fprintf(stderr, "TCP ports: %s\n", tcp_ports ? tcp_ports : "None");
    fprintf(stderr, "UDP ports: %s\n", udp_ports ? udp_ports : "None");
    fprintf(stderr, "Timeout: %d ms\n", timeout);
    fprintf(stderr, "Host: %s\n\n", host);
    fprintf(stderr, "--- Scanning these ports: ---\n");
    for (int idx = 0; idx <= MAX_PORTS; idx++) {
      if (scan_tcp[idx]) fprintf(stderr, "TCP port: %d\n", idx);
      if (scan_udp[idx]) fprintf(stderr, "UDP port: %d\n", idx);
    }
    fprintf(stderr, "-----------------------\n\n");
  }
}


int main(int argc, char **argv) {
  signal(SIGINT, signal_handler); // Register signal handler for SIGINT
  signal(SIGTERM, signal_handler); // Register signal handler for SIGTERM

  int opt;
  char *interface = NULL;
  char *tcp_ports = NULL;
  char *udp_ports = NULL;
  int timeout = DEFAULT_TIMEOUT;
  char *host = NULL;

  // only -i then print all interfaces
  if (argc == 2 && strcmp(argv[1], "-i") == 0) {
    show_interfaces();
  }

  // Structure for long argument of --help
  // According to man of getopt(3)
  // name, num_of_args, flag, val
  static struct option long_args[] = {{"help", no_argument, 0, 'h'},
                                      {0, 0, 0, 0}};

  while ((opt = getopt_long(argc, argv, "vhi:t:u:w:", long_args, NULL)) !=
         -1) {
    switch (opt) {
    case 'v':
      // verbose info
      verbose_flag = true;
      break;
    case 'h':
      print_help();
      break;
    case 'i':
        interface = optarg;
      break;
    case 't':
      tcp_ports = optarg;
      break;
    case 'u':
      udp_ports = optarg;
      break;
    case 'w':
      // check for nonsenses like negative or non-numeric values
      if (optarg[0] == '\0') {
        fprintf(stderr, "ERROR: Timeout value is missing\n");
        return(1);
      }

      for (size_t i = 0; optarg[i] != '\0'; i++) {
        if (!isdigit(optarg[i])) {
          fprintf(stderr, "ERROR: Timeout value must be a positive integer\n");
          return(1);
        }
      }

      timeout = atoi(optarg);
      break;
    default:
      fprintf(stderr, "ERROR: Unknown argument\n");
      return(1);
    }
  }

  // argument -i is required
  if (interface == NULL) {
    fprintf(stderr, "ERROR: Network interface (-i) is required\n");
    return(1);
  }

  // Validate interface argument
  if (if_nametoindex(interface) == 0) {
    fprintf(stderr, "ERROR: Interface %s is missing or invalid\n", interface);
    return(1);
  }


  parse_ports(tcp_ports, scan_tcp);
  parse_ports(udp_ports, scan_udp);

  // all dash args are parsed, HOST remains
  if (optind < argc) {
    host = argv[optind];
  }

  // Validation
  if (host == NULL) {
    fprintf(stderr, "ERROR: Host is missing\n");
    return(1);
  }

  verbose_print(verbose_flag, tcp_ports, udp_ports, interface, timeout, host);

  // DNS resolution
  struct addrinfo hints, *res, *record;
  int status;
  char IPstring[INET6_ADDRSTRLEN]; // Buffer to save ip addr as string

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC; // IP addr can be v4 also v6
  hints.ai_socktype = SOCK_STREAM; // Standard 2way con-based byte stream

  if (verbose_flag) {
    fprintf(stderr, "Looking up IP address for %s\n", host);
  }
  if ((status = getaddrinfo(host, NULL, &hints, &res)) != 0) {
    fprintf(stderr, "ERROR: getaddrinfo err: %s\n", gai_strerror(status));
    return 1;
  }
  // Go through all ip addrs for DNS record 
  for (record = res; record != NULL; record = record->ai_next) {
    void *addr;
    char *ipver;
    int curr_ver = record->ai_family; // save current IP version

    // Which ver of ip ?
    // IPv4
    if (record->ai_family == AF_INET) {
      struct sockaddr_in *ipv4 = (struct sockaddr_in *)record->ai_addr;
      addr = &(ipv4->sin_addr);
      ipver = "IPv4";
    } else {
      struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)record->ai_addr;
      addr = &(ipv6->sin6_addr);
      ipver = "IPv6";
    }

    // Convert binary ip addr to text form
    inet_ntop(record->ai_family, addr, IPstring, sizeof(IPstring));
    if (verbose_flag) {
      fprintf(stderr, "Found IP address: %s (%s)\n", IPstring, ipver);
    }
    
    char my_ip[INET6_ADDRSTRLEN]; 
    // Get my ip addr
    if (get_src_ip(curr_ver, IPstring, my_ip, sizeof(my_ip))) {
      fprintf(stderr, "Unable to get %s address for interface %s. Skipping...\n", ipver, interface);
      continue;
    }
    // Scan all specified ports
    for (int tcp_idx = 1; tcp_idx <= MAX_PORTS; tcp_idx++) {
      if (running == 0) {
        fprintf(stderr, "Scan interrupted by user/system. Exiting...\n");
        freeaddrinfo(res);
        return 0;
      }

      if (scan_tcp[tcp_idx]) {
        port_status_t port_state = scan_tcp_port(interface, my_ip, IPstring, SRC_PORT, tcp_idx, timeout, verbose_flag, curr_ver);

        const char *state_str = "unknown";
        if (port_state == PORT_OPEN) {
            state_str = "open";
        } else if (port_state == PORT_CLOSED) {
            state_str = "closed";
        } else if (port_state == PORT_FILTERED) {
            state_str = "filtered";
        }
        printf("%s %d tcp %s\n", IPstring, tcp_idx, state_str);
      }
    }

    for (int udp_idx = 1; udp_idx <= MAX_PORTS; udp_idx++) {
      if (running == 0) {
        fprintf(stderr, "Scan interrupted by user/system. Exiting...\n");
        freeaddrinfo(res);
        return 0;
      }
      if (scan_udp[udp_idx]) {
        port_status_t port_state = scan_udp_port(interface, my_ip, IPstring, SRC_PORT, udp_idx, timeout, verbose_flag, curr_ver);

        const char *state_str = "unknown";
        if (port_state == PORT_OPEN) {
            state_str = "open";
        } else if (port_state == PORT_CLOSED) {
            state_str = "closed";
        }
        printf("%s %d udp %s\n", IPstring, udp_idx, state_str);
      }
    }
  }
  freeaddrinfo(res);
  return 0;
}