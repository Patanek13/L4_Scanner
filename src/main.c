/*
 * @file main.c
 * @author Patrik Lošťák <xlostap00>
 * @brief Implementation of simple L4 scanner
 */

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

#define DEFAULT_TIMEOUT 1000
#define IFNAMSIZ 16 // max interface lenght with \0 in linux
bool verbose_flag = false;

// Just print help message and exit program with 0
// TODO: better help
void print_help() {
  printf("Usage: ./ipk-L4-scan -v -i INTERFACE [-u PORTS] [-t PORTS] HOST [-w "
         "TIMEOUT] [-h | --help]\n");
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

int main(int argc, char **argv) {
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
      // TODO: check for nonsenses
      timeout = atoi(optarg);
      break;
    default:
      fprintf(stderr, "ERROR: Unknown argument\n");
      exit(1);
    }
  }

  // all dash args are parsed, HOST remains
  if (optind < argc) {
    host = argv[optind];
  }

  // Validation
  if (host == NULL && interface == NULL) {
    fprintf(stderr, "ERROR: Host is missing\n");
    exit(1);
  }

  if (verbose_flag) {
    printf("--- Loaded values ---\n");
    printf("Interface: %s\n", interface);
    printf("TCP ports: %s\n", tcp_ports ? tcp_ports : "None");
    printf("UDP ports: %s\n", udp_ports ? udp_ports : "None");
    printf("Timeout: %d ms\n", timeout);
    printf("Host: %s\n", host);
    printf("-----------------------\n\n");
  }

  // DNS resolution


}