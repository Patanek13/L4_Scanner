/*
 * @file scanner.h
 * @author Patrik Lošťák <xlostap00>
 * @brief Function definitions for scan functions
 */
#ifndef SCANNER_H
#define SCANNER_H

#include <stdint.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>

typedef enum {
    PORT_OPEN,
    PORT_CLOSED,
    PORT_FILTERED,
    PORT_ERROR
} port_status_t;

/*
 * @brief function to create TCP socket for sending SYN packets
 * @param domain - AF_INET for IPv4, AF_INET6 for IPv6
 * @return socket file descriptor on success, -1 on failure
 */
int create_tcp_socket(int domain);

/*
 * @brief function to define TCP header for SYN scan
 * @param tcp_header - pointer to TCP header struct to be filled
 * @param src_port - source port number
 * @param dst_port - destination port number
 * @return void
 */
void define_tcp_syn_header(struct tcphdr *tcp_header, uint16_t src_port, uint16_t dst_port);

/*
 * @brief function to get local IP address for a given destination IP and interface
 * @param ip_ver - IP version (AF_INET for IPv4, AF_INET6 for IPv6)
 * @param dst_ip - destination IP address as a string
 * @param my_ip - buffer to store the resulting local IP address as a string
 * @param my_ip_len - length of the my_ip buffer
 * @return 0 on success, -1 on failure
 */
int get_src_ip(int ip_ver, const char *dst_ip, char *my_ip, size_t my_ip_len);

/*
 * @brief function to calculate checksum for TCP header (based on RFC 1071)
 * @param data - pointer to the data for which checksum is to be calculated
 * @param len - length of the data in bytes
 * @return checksum value as an unsigned short
 */
unsigned short calculate_checksum(void *data, int len);

/*
 * @brief function to calculate TCP header checksum for IPv4 SYN scan
 * @param tcp_header - pointer to TCP header struct for which checksum is to be calculated
 * @param src_ip - source IP address as a string
 * @param dst_ip - destination IP address as a string
 * @return void (checksum is set in the tcp_header struct)
 */
void calculate_tcp_hdr_checksum_ipv4(struct tcphdr *tcp_header, const char *src_ip, const char *dst_ip);

/*
 * @brief function to send TCP SYN packet for IPv4
 * @param src_ip - source IP address as a string
 * @param dst_ip - destination IP address as a string
 * @param src_port - source port number
 * @param dst_port - destination port number
 * @param verbose_flag - boolean flag to enable verbose output for debugging
 * @return void
 */
void send_tcp_syn_ipv4(const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port, bool verbose_flag);

/*
 * @brief function to scan a TCP port by sending a SYN packet and waiting for response
 * @param interface - name of the network interface to use for sending and sniffing
 * @param src_ip - source IP address as a string
 * @param dst_ip - destination IP address as a string
 * @param src_port - source port number
 * @param dst_port - destination port number
 * @param timeout_ms - timeout in milliseconds to wait for a response before determining port status
 * @param verbose_flag - boolean flag to enable verbose output for debugging
 * @param ip_ver - IP version (AF_INET for IPv4, AF_INET6 for IPv6)
 * @return port_status_t indicating whether the port is open, closed, filtered, or if an error occurred
 */
port_status_t scan_tcp_port(const char *interface, const char *src_ip, const char *dst_ip, int src_port, int dst_port, int timeout_ms, bool verbose_flag, int ip_ver);

/*
 * @brief function to calculate TCP header checksum for IPv6 SYN scan
 * @param tcp_header - pointer to TCP header struct for which checksum is to be calculated
 * @param src_ip - source IP address as a string
 * @param dst_ip - destination IP address as a string
 * @return void (checksum is set in the tcp_header struct)
 */
void calculate_tcp_hdr_checksum_ipv6(struct tcphdr *tcp_header, const char *src_ip, const char *dst_ip);

/*
 * @brief function to send TCP SYN packet for IPv6
 * @param src_ip - source IP address as a string
 * @param dst_ip - destination IP address as a string
 * @param src_port - source port number
 * @param dst_port - destination port number
 * @param verbose_flag - boolean flag to enable verbose output for debugging
 * @return void
 */
void send_tcp_syn_ipv6(const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port, bool verbose_flag);

/*
 * @brief function to send UDP packet for IPv4
 * @param dst_ip - destination IP address as a string
 * @param src_port - source port number
 * @param dst_port - destination port number
 * @param verbose_flag - boolean flag to enable verbose output for debugging
 * @return void
 */
void send_udp_ipv4(const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port, bool verbose_flag);

/*
 * @brief function to send UDP packet for IPv6
 * @param src_ip - source IP address as a string
 * @param dst_ip - destination IP address as a string
 * @param src_port - source port number
 * @param dst_port - destination port number
 * @param verbose_flag - boolean flag to enable verbose output for debugging
 * @return void
 */
void send_udp_ipv6(const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port, bool verbose_flag);

/*
 * @brief function to scan a UDP port by sending a UDP packet and waiting for response
 * @param interface - name of the network interface to use for sending and sniffing
 * @param src_ip - source IP address as a string
 * @param dst_ip - destination IP address as a string
 * @param src_port - source port number
 * @param dst_port - destination port number
 * @param timeout_ms - timeout in milliseconds to wait for a response before determining port status
 * @param verbose_flag - boolean flag to enable verbose output for debugging
 * @param ip_ver - IP version (AF_INET for IPv4, AF_INET6 for IPv6)
 * @return port_status_t indicating whether the port is open, closed, filtered, or if an error occurred
 */
port_status_t scan_udp_port(const char *interface, const char *src_ip, const char *dst_ip, int src_port, int dst_port, int timeout_ms, bool verbose_flag, int ip_ver);

#endif

