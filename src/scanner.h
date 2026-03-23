/*
 * @file scanner.h
 * @author Patrik Lošťák <xlostap00>
 * @brief Function definitions for scan functions
 */
#ifndef SCANNER_H
#define SCANNER_H

#include <stdint.h>
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

#endif

