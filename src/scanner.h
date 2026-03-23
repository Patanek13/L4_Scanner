/*
 * @file scanner.h
 * @author Patrik Lošťák <xlostap00>
 * @brief Function definitions for scan functions
 */
#ifndef SCANNER_H
#define SCANNER_H

#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#define _GNU_SOURCE

#include <stdint.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

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
 * @brief function to get IP address of a network interface
 * @param interface_name - name of the network interface (e.g., "eth0", "wlan0")
 * @param family - AF_INET for IPv4, AF_INET6 for IPv6
 * @param ip_buffer - buffer to store the resulting IP address as a string
 * @param buffer_len - length of the ip_buffer
 * @return 0 on success, -1 on failure
 */
int get_interface_ip(const char *interface_name, int family, char *ip_buffer, size_t buffer_len);

/*
 * @brief function to calculate checksum for TCP header (based on RFC 1071)
 * @param data - pointer to the data for which checksum is to be calculated
 * @param len - length of the data in bytes
 * @return checksum value as an unsigned short
 */
unsigned short calculate_checksum(void *data, int len);

/*
 * @brief function to calculate TCP header checksum for SYN scan
 * @param tcp_header - pointer to TCP header struct for which checksum is to be calculated
 * @param src_ip - source IP address as a string
 * @param dst_ip - destination IP address as a string
 * @return void (checksum is set in the tcp_header struct)
 */
void calculate_tcp_hdr_checksum(struct tcphdr *tcp_header, const char *src_ip, const char *dst_ip);

#endif

