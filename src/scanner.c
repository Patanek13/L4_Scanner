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
#include <net/if.h>
#include <netinet/icmp6.h>


#define SEQ_NUM 1311
#define HDRSIZE 5 // words
#define WINSIZE 65535 // bytes
#define HDR_LEN_FIELD_SIZE 4 // header length field of IP header is 4-bit field
#define LCC_LINK_HDR_SIZE 16 // Link-layer address length for Linux "cooked" capture 
#define LO_LINK_HDR_SIZE 4 // Link-layer address length for OpenBSD loopback
#define ETH_LINK_HDR_SIZE 14 // Link-layer address length for IEEE 802.3 Ethernet
#define PADDING 3 // 3 bytes of zeros as padding 
#define IPV6_HDR_LEN 40 // Length of IPv6 header is fixed 40 bytes
#define DNS_PORT 53 // Just any port for get_src_ip function, we won't actually send data to it

// Structure for IPv4 pseudo header
struct pseudo_header_ipv4 {
  uint32_t src_addr; // 4 bytes
  uint32_t dst_addr; // 4 bytes
  uint8_t readdred_zero; // 1 byte (always 0)
  u_int8_t protocol; // 1 byte (6 for TCP)
  uint16_t length; // 2 bytes (data + header) 
};

// Structure for IPv6 pseudo header
struct pseudo_header_ipv6 {
  struct in6_addr src_addr; // 16 bytes
  struct in6_addr dst_addr; // 16 bytes
  uint32_t tcp_len; // 4 bytes (data + header)
  uint8_t zeros[PADDING]; // 3 bytes of zeros (padding)
  uint8_t next_hdr; // 1 byte (value 6 for TCP)
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

// Get local IP address for given destination IP and interface, returns 0 on success, -1 on failure
int get_src_ip(int ip_ver, const char *dst_ip, char *my_ip, size_t my_ip_len) {
    // Create fake UDP socket
    int sock = socket(ip_ver, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    if (ip_ver == AF_INET) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(DNS_PORT); // Just any port, we won't actually send data
        inet_pton(AF_INET, dst_ip, &addr.sin_addr);
        
        // no connection with UDP, just checks route table
        connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        
        struct sockaddr_in name;
        socklen_t namelen = sizeof(name);
        getsockname(sock, (struct sockaddr*)&name, &namelen); // Find our ip
        inet_ntop(AF_INET, &name.sin_addr, my_ip, my_ip_len);
    } else {
        struct sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(DNS_PORT);
        inet_pton(AF_INET6, dst_ip, &addr.sin6_addr);
        
        connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        
        struct sockaddr_in6 name;
        socklen_t namelen = sizeof(name);
        getsockname(sock, (struct sockaddr*)&name, &namelen);
        inet_ntop(AF_INET6, &name.sin6_addr, my_ip, my_ip_len);
    }
    close(sock);
    return 0;
}
// Logic for checksum calculation adapted from RFC 1071 and from
// https://www.geeksforgeeks.org/computer-networks/calculation-of-tcp-checksum/
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

void calculate_tcp_hdr_checksum_ipv4(struct tcphdr *tcp_header, const char *src_ip, const char *dst_ip) {
  struct pseudo_header_ipv4 pshdr;

  // Convert ip addrs from string to binary
  inet_pton(AF_INET, src_ip, &(pshdr.src_addr));
  inet_pton(AF_INET, dst_ip, &(pshdr.dst_addr));

  pshdr.readdred_zero = 0;
  pshdr.protocol = IPPROTO_TCP;
  pshdr.length = htons(sizeof(struct tcphdr));
  
  // buffer for pseudo header and tcp header
  int buffer_len = sizeof(struct pseudo_header_ipv4) + sizeof(struct tcphdr);
  char *buffer = malloc(buffer_len);
  if (!buffer) {
    perror("ERROR(checksum): malloc failed\n");
    exit(1);
  }
  // copy data to buffer (pseudo header + tcp header)
  memcpy(buffer, (char *)&pshdr, sizeof(struct pseudo_header_ipv4));
  memcpy(buffer + sizeof(struct pseudo_header_ipv4), tcp_header, sizeof(struct tcphdr));

  tcp_header->check = calculate_checksum(buffer, buffer_len);
  free(buffer);
}

void send_tcp_syn_ipv4(const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port, bool verbose_flag) {
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
  calculate_tcp_hdr_checksum_ipv4(&tcp_header, src_ip, dst_ip);

  // Send to network
  ssize_t bytes_sent = sendto(socket, &tcp_header, sizeof(struct tcphdr), 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr));

  if (bytes_sent < 0) {
    perror("ERROR: Sending error (sendto IPv4)\n");
  } else {
    if (verbose_flag)
    fprintf(stderr, "Packet SYN successfully sent to [%s]:%d\n", dst_ip, dst_port);
  }

  close(socket);
}

port_status_t scan_tcp_port(const char *interface, const char *src_ip, const char *dst_ip, int src_port, int dst_port, int timeout_ms, bool verbose_flag, int ip_ver) {
  // Setup sniffer
  pcap_t *pcap_handle = init_sniffer(interface, dst_ip, src_port, dst_port, verbose_flag, IPPROTO_TCP);
  if (!pcap_handle) return PORT_ERROR;

  // find the ethernet link header size dynamically
  int link_type = pcap_datalink(pcap_handle);
  int link_hdr_size = 0;

  switch (link_type) {
    case DLT_EN10MB:      // Standard ethernet and wifis
      link_hdr_size = ETH_LINK_HDR_SIZE;
      break;
    case DLT_NULL:        // Loopback
      link_hdr_size = LO_LINK_HDR_SIZE;
      break;
    case DLT_LINUX_SLL:   // Linux-cooked-capture (from any device)
      link_hdr_size = LCC_LINK_HDR_SIZE;
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
    // send SYN packet based on ip version
    if (ip_ver == AF_INET) {
      send_tcp_syn_ipv4(src_ip, dst_ip, src_port, dst_port, verbose_flag);
    } else {
      send_tcp_syn_ipv6(src_ip, dst_ip, src_port, dst_port, verbose_flag);
    }

    struct pcap_pkthdr *header;
    const unsigned char *packet_data;
    int response = sniff_response(pcap_handle, &header, &packet_data, timeout_ms, verbose_flag);

    if (response == 1) { // Packet arrived
     int ethernet_offset = link_hdr_size;
      const struct tcphdr *tcp_header;

      if (ip_ver == AF_INET) {
          // IPv4 has variable length
          const struct ip *ip_header = (struct ip*)(packet_data + ethernet_offset);
          int ip_hdr_len = ip_header->ip_hl * HDR_LEN_FIELD_SIZE;
          tcp_header = (struct tcphdr*)(packet_data + ethernet_offset + ip_hdr_len);
      } else {
          // Proccess IPv6 header with fixed 40 bytes
          int ipv6_hdr_len = IPV6_HDR_LEN; 
          tcp_header = (struct tcphdr*)(packet_data + ethernet_offset + ipv6_hdr_len);
      }

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

void calculate_tcp_hdr_checksum_ipv6(struct tcphdr *tcp_header, const char *src_ip, const char *dst_ip) {
  struct pseudo_header_ipv6 pshdr;

  // Convert ip addrs from string to binary
  inet_pton(AF_INET6, src_ip, &(pshdr.src_addr));
  inet_pton(AF_INET6, dst_ip, &(pshdr.dst_addr));

  pshdr.next_hdr = IPPROTO_TCP;
  pshdr.tcp_len = htonl(sizeof(struct tcphdr));
  memset(pshdr.zeros, 0, PADDING);
  
  // buffer for pseudo header and tcp header
  int buffer_len = sizeof(struct pseudo_header_ipv6) + sizeof(struct tcphdr);
  char *buffer = malloc(buffer_len);
  if (!buffer) {
    perror("ERROR(checksum): malloc failed\n");
    exit(1);
  }
  // copy data to buffer (pseudo header + tcp header)
  memcpy(buffer, (char *)&pshdr, sizeof(struct pseudo_header_ipv6));
  memcpy(buffer + sizeof(struct pseudo_header_ipv6), tcp_header, sizeof(struct tcphdr));

  tcp_header->check = calculate_checksum(buffer, buffer_len);
  free(buffer);
}

void send_tcp_syn_ipv6(const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port, bool verbose_flag) {
  // create socket
  int socket = create_tcp_socket(AF_INET6);


  // setup struct with dst addr to sendto()
  struct sockaddr_in6 dst_addr;
  memset(&dst_addr, 0, sizeof(dst_addr));
  dst_addr.sin6_family = AF_INET6;
  dst_addr.sin6_port = 0;


  // convert to binary
  if (inet_pton(AF_INET6, dst_ip, &dst_addr.sin6_addr) <= 0) {
    perror("ERROR: Invalid destination IPv6 address\n");
    close(socket);
    return;
  }

  // Fill TCP header
  struct tcphdr tcp_header;
  define_tcp_syn_header(&tcp_header, src_port, dst_port);

  // calc and fill checksum
  calculate_tcp_hdr_checksum_ipv6(&tcp_header, src_ip, dst_ip);

  // Send to network
  ssize_t bytes_sent = sendto(socket, &tcp_header, sizeof(struct tcphdr), 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr));

  if (bytes_sent < 0) {
    perror("ERROR: Sending error (sendto IPv6)\n");
  } else {
    if (verbose_flag)
    fprintf(stderr, "Packet SYN successfully sent to [%s]:%d\n", dst_ip, dst_port);
  }

  close(socket);
}

void send_udp_ipv4(const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port, bool verbose_flag) {
  // create raw socket for UDP
  int socketfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (socketfd < 0) {
    perror("ERROR: Failed to create UDP socket");
    return;
  }

  // Bind to source port
  struct sockaddr_in src_addr;
  memset(&src_addr, 0, sizeof(src_addr));
  src_addr.sin_family = AF_INET;
  src_addr.sin_port = htons(src_port);
  inet_pton(AF_INET, src_ip, &src_addr.sin_addr);

  if (bind(socketfd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
    perror("ERROR: Failed to bind UDP socket");
    close(socketfd);
    return;
  }

  // setup struct with dst addr to sendto()
  struct sockaddr_in dst_addr;
  memset(&dst_addr, 0, sizeof(dst_addr));
  dst_addr.sin_family = AF_INET;
  dst_addr.sin_port = htons(dst_port);

  // convert to binary
  if (inet_pton(AF_INET, dst_ip, &dst_addr.sin_addr) <= 0) {
    perror("ERROR: Invalid destination IPv4 address\n");
    close(socketfd);
    return;
  }

  // Just send empty UDP packet 
  ssize_t bytes_sent = sendto(socketfd, NULL, 0, 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr));

  if (bytes_sent < 0) {
    perror("ERROR: Sending error (sendto UDP IPv4)\n");
  } else {
    if (verbose_flag)
    fprintf(stderr, "UDP packet successfully sent to [%s]:%d\n", dst_ip, dst_port);
  }

  close(socketfd);
}

void send_udp_ipv6(const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port, bool verbose_flag) {
  // create raw socket for UDP
  int socketfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (socketfd < 0) {
    perror("ERROR: Failed to create UDP socket");
    return;
  }

  // Bind to source port
  struct sockaddr_in6 src_addr;
  memset(&src_addr, 0, sizeof(src_addr));
  src_addr.sin6_family = AF_INET6;
  src_addr.sin6_port = htons(src_port);
  inet_pton(AF_INET6, src_ip, &src_addr.sin6_addr);

  if (bind(socketfd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
    perror("ERROR: Failed to bind UDP socket");
    close(socketfd);
    return;
  }

  // setup struct with dst addr to sendto()
  struct sockaddr_in6 dst_addr;
  memset(&dst_addr, 0, sizeof(dst_addr));
  dst_addr.sin6_family = AF_INET6;
  dst_addr.sin6_port = htons(dst_port);

  // convert to binary
  if (inet_pton(AF_INET6, dst_ip, &dst_addr.sin6_addr) <= 0) {
    perror("ERROR: Invalid destination IPv6 address\n");
    close(socketfd);
    return;
  }

  // Just send empty UDP packet 
  ssize_t bytes_sent = sendto(socketfd, NULL, 0, 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr));

  if (bytes_sent < 0) {
    perror("ERROR: Sending error (sendto UDP IPv6)\n");
  } else {
    if (verbose_flag)
    fprintf(stderr, "UDP packet successfully sent to [%s]:%d\n", dst_ip, dst_port);
  }

  close(socketfd);
}

port_status_t scan_udp_port(const char *interface, const char *src_ip, const char *dst_ip, int src_port, int dst_port, int timeout_ms, bool verbose_flag, int ip_ver) {
  // Setup sniffer
  pcap_t *pcap_handle = init_sniffer(interface, dst_ip, src_port, dst_port, verbose_flag, IPPROTO_UDP);
  if (!pcap_handle) return PORT_ERROR;

  // find the ethernet link header size dynamically
  int link_type = pcap_datalink(pcap_handle);
  int link_hdr_size = 0;

  switch (link_type) {
    case DLT_EN10MB:      // Standard ethernet and wifis
      link_hdr_size = ETH_LINK_HDR_SIZE;
      break;
    case DLT_NULL:        // Loopback
      link_hdr_size = LO_LINK_HDR_SIZE;
      break;
    case DLT_LINUX_SLL:   // Linux-cooked-capture (from any device)
      link_hdr_size = LCC_LINK_HDR_SIZE;
      break;
    case DLT_RAW:         // Raw IP packets 
      link_hdr_size = 0;
      break;
    default:
      fprintf(stderr, "ERROR: Unsupported link layer type (%d) on interface %s\n", link_type, interface);
      pcap_close(pcap_handle);
      return PORT_ERROR;
  }

  // Other ports open
  port_status_t final_state = PORT_OPEN; // default val

  // Send UDP packet
  if (ip_ver == AF_INET) {
    send_udp_ipv4(src_ip, dst_ip, src_port, dst_port, verbose_flag);
  } else {
    send_udp_ipv6(src_ip, dst_ip, src_port, dst_port, verbose_flag);
  }

  struct pcap_pkthdr *header;
  const unsigned char *packet_data;
  // Wait for response
  int response = sniff_response(pcap_handle, &header, &packet_data, timeout_ms, verbose_flag);

  if (response == 1) { // ICMP arrived
    int ethernet_offset = link_hdr_size;

    if (ip_ver == AF_INET) {
      // Proccess ICMP header
      const struct ip *ip_header = (struct ip*)(packet_data + ethernet_offset);
      int ip_hdr_len = ip_header->ip_hl * HDR_LEN_FIELD_SIZE;
      const struct icmphdr *icmp_header = (struct icmphdr*)(packet_data + ethernet_offset + ip_hdr_len);
      // ICMP type 3 code 3 ---> port closed
      if (icmp_header->type == ICMP_DEST_UNREACH && icmp_header->code == ICMP_PORT_UNREACH) {
        final_state = PORT_CLOSED;
      }
    } else {
      // Proccess ICMPv6 header
      int ipv6_hdr_len = IPV6_HDR_LEN; 
      const struct icmp6_hdr *icmp6_header = (struct icmp6_hdr*)(packet_data + ethernet_offset + ipv6_hdr_len);
      // ICMPv6 type 1 code 4 ---> port closed
      if (icmp6_header->icmp6_type == ICMP6_DST_UNREACH && icmp6_header->icmp6_code == ICMP6_DST_UNREACH_NOPORT) {
        final_state = PORT_CLOSED;
      }
    }
  }
  // If response == 0 --> timeout --> port is open|filtered
  pcap_close(pcap_handle);
  return final_state;
}