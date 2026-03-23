/*
 * @file scanner.c
 * @author Patrik Lošťák <xlostap00>
 * @brief Implementaion of scanner functions for L4 scanning
 */

#include "scanner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <arpa/inet.h>


#define SEQ_NUM 1311
#define HDRSIZE 5 // words
#define WINSIZE 65535 // bytes

// Create raw socket, returns file descriptor or -1
int create_tcp_socket(int domain) {
  int sockfd = socket(domain, SOCK_RAW, IPPROTO_TCP);
  if (sockfd < 0) {
    perror("ERROR: Failed to create TCP socket");
    exit(1);
  }
  return sockfd;
}

void define_tcp_syn_header(struct tcphdr *tcp_header, uint16_t src_port, uint16_t dst_port) {
  memset(tcp_header, 0, sizeof(struct tcphdr));
  tcp_header->source = htons(src_port);
  tcp_header->dest = htons(dst_port);
  tcp_header->seq = htonl(SEQ_NUM); // chosen random number
  tcp_header->ack_seq = 0; // Nothing to confirm
  tcp_header->doff = HDRSIZE; // 5 * 32-bit word = 20 bytes for header
  tcp_header->syn = 1; // Set flag 
  tcp_header->window = htons(WINSIZE); // How much data we can accept
  tcp_header->check = 0; // TOOD: CheckSum
  tcp_header->urg_ptr = 0;
}

int get_interface_ip(const char *interface_name, int family, char *ip_buffer, size_t buffer_len) {
  struct ifaddrs *ifaddr, *ifa;

  // Get all ifs
  if (getifaddrs(&ifaddr) == -1) {
    perror("ERROR: getifaddrs failed");
    return -1;
  }

  // find matching ip ver with ip ver on interface
  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_name == NULL || ifa->ifa_addr == NULL) {
      continue;
    }

    if(strcmp(ifa->ifa_name, interface_name) == 0 && ifa->ifa_addr->sa_family == family) {
      void *addr;
      if (family == AF_INET) { // IPv4
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)ifa->ifa_addr; 
        addr = &(ipv4->sin_addr);
      } else {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)ifa->ifa_addr;
        addr = &(ipv6->sin6_addr);
      }
      // Convert to string form
      inet_ntop(family, addr, ip_buffer, buffer_len);

      freeifaddrs(ifaddr);
      return 0;
    }
  }
  freeifaddrs(ifaddr);
  return -1; // Interface or IP family not found
}