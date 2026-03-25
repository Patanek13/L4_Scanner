/*
 * @file scanner.c
 * @author Patrik Lošťák <xlostap00>
 * @brief Implementaion of scanner functions for L4 scanning
 */

#include "scanner.h"
#include "sniffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>


#define SEQ_NUM 1311
#define HDRSIZE 5 // words
#define WINSIZE 65535 // bytes
#define HDR_LEN_FIELD_SIZE 4 // header length field of IP header is 4-bit field

// Structure for IPv4 pseudo header
struct pseudo_header {
  uint32_t src_addr; // 4 bytes
  uint32_t dst_addr; // 4 bytes
  uint8_t reserved_zero; // 1 byte (always 0)
  u_int8_t protocol; // 1 byte (6 for TCP)
  uint16_t length; // 2 bytes (data + header) 
};

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
  tcp_header->check = 0; // Checksum 0 before calculation
  tcp_header->urg_ptr = 0;
}

int get_interface_ip(const char *interface_name, int family, char *ip_buffer, size_t buffer_len) {
  struct ifaddrs *ifaddr, *ifa;

  // Get all ifs
  if (getifaddrs(&ifaddr) == -1) {
    perror("ERROR: getifaddrs failed\n");
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
      } else { // IPv6
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)ifa->ifa_addr;
        addr = &(ipv6->sin6_addr);
      }
      // Convert ip addr to string format
      inet_ntop(family, addr, ip_buffer, buffer_len);

      freeifaddrs(ifaddr);
      return 0;
    }
  }
  freeifaddrs(ifaddr);
  return -1; // Interface or IP family not found
}

unsigned short calculate_checksum(void *data, int len) {
  unsigned short *buffer = data;
  unsigned int sum = 0;
  unsigned short result;

  // 1. We sum the words together
  for (sum = 0; len > 1; len -= 2) {
    sum += *buffer++;
  }

  // If 1 byte left
  if (len == 1) {
    sum += (unsigned short)*buffer;
  }

  // 2. Handle overflow (extra bits beyond 16 add back to lower 16 bits)
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);

  //3. Invert all the bits in sum
  result = ~sum;
  return result;
}

void calculate_tcp_hdr_checksum(struct tcphdr *tcp_header, const char *src_ip, const char *dst_ip) {
  struct pseudo_header pshdr;

  // Convert ip addrs from string to binary
  inet_pton(AF_INET, src_ip, &(pshdr.src_addr));
  inet_pton(AF_INET, dst_ip, &(pshdr.dst_addr));

  pshdr.reserved_zero = 0;
  pshdr.protocol = IPPROTO_TCP;
  pshdr.length = htons(sizeof(struct tcphdr));
  
  // buffer for pseudo header and tcp header
  int buffer_len = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
  char *buffer = malloc(buffer_len);
  if (!buffer) {
    perror("ERROR(checksum): malloc failed\n");
    exit(1);
  }
  // copy data to buffer (pseudo header + tcp header)
  memcpy(buffer, (char *)&pshdr, sizeof(struct pseudo_header));
  memcpy(buffer + sizeof(struct pseudo_header), tcp_header, sizeof(struct tcphdr));

  tcp_header->check = calculate_checksum(buffer, buffer_len);
  free(buffer);
}

void send_tcp_syn_ipv4(const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port) {
  // create socket
  int socket = create_tcp_socket(AF_INET);

  // setup struct with dst addr to sendto()
  struct sockaddr_in dst_addr;
  memset(&dst_addr, 0, sizeof(dst_addr));
  dst_addr.sin_family = AF_INET;
  dst_addr.sin_port = htons(dst_port);

  // convert to binary
  if (inet_pton(AF_INET, dst_ip, &dst_addr.sin_addr) <= 0) {
    perror("ERROR: Invalid destination IPv4 address\n");
    close(socket);
    return;
  }

  // Fill TCP header
  struct tcphdr tcp_header;
  define_tcp_syn_header(&tcp_header, src_port, dst_port);

  // calc and fill checksum
  calculate_tcp_hdr_checksum(&tcp_header, src_ip, dst_ip);

  // Send to network
  ssize_t bytes_sent = sendto(socket, &tcp_header, sizeof(struct tcphdr), 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr));

  if (bytes_sent < 0) {
    perror("ERROR: Sending error (sendto)");
  } else {
    fprintf(stderr, "Packet SYN successfully sent to %s:%d\n", dst_ip, dst_port);
  }

  close(socket);
}

port_status_t scan_tcp_port(const char *interface, const char *src_ip, const char *dst_ip, int src_port, int dst_port, int timeout_ms) {
  // Setup sniffer
  pcap_t *pcap_handle = init_sniffer(interface, dst_ip, src_port);
  if (!pcap_handle) return PORT_ERROR;

  // find the ethernet link header size dynamically
  int link_type = pcap_datalink(pcap_handle);
  int link_hdr_size = 0;

  switch (link_type) {
    case DLT_EN10MB:      // Standard ethernet and wifis
      link_hdr_size = 14;
      break;
    case DLT_NULL:        // Loopback
      link_hdr_size = 4;
      break;
    case DLT_LINUX_SLL:   // Linux-cooked-capture (from any device)
      link_hdr_size = 16;
      break;
    case DLT_RAW:         // Raw IP packets 
      link_hdr_size = 0;
      break;
    default:
      fprintf(stderr, "ERROR: Unsupported link layer type (%d) on interface %s\n", link_type, interface);
      pcap_close(pcap_handle);
      return PORT_ERROR;
  }

  port_status_t final_state = PORT_FILTERED; // default val

  // Max 2 attempts to send
  for(int attempt = 0; attempt <= 1; attempt++) {
    send_tcp_syn_ipv4(src_ip, dst_ip, src_port, dst_port);

    struct pcap_pkthdr *header;
    const unsigned char *packet_data;
    int response = sniff_response(pcap_handle, &header, &packet_data, timeout_ms);

    if (response == 1) { // Packet arrived
      int ethernet_offset = link_hdr_size;
      // Map ip header to find the real size
      const struct ip *ip_header = (struct ip*)(packet_data + ethernet_offset);
      int ip_hdr_len = ip_header->ip_hl * HDR_LEN_FIELD_SIZE;
      // Skip ethernet header and ip header
      const struct tcphdr *tcp_header = (struct tcphdr*)(packet_data + ethernet_offset + ip_hdr_len);

      if (tcp_header->syn == 1 && tcp_header->ack == 1) {
        final_state = PORT_OPEN;
        break;
      } else if (tcp_header->rst == 1) {
        final_state = PORT_CLOSED;
        break;
      }
    } else if (response == 0) {
      // If second iteration goes --> port final state will stay FILTERED
    } else {
      final_state = PORT_ERROR;
      break;
    }
  }
  pcap_close(pcap_handle);
  return final_state;
}
