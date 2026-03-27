/*
 * @file sniffer.h
 * @author Patrik Lošťák <xlostap00>
 * @brief Function definitions for packet sniffer functions
 */

#ifndef SNIFFER_H
#define SNIFFER_H


#include <sys/types.h>
#include <pcap.h>
#include <stdbool.h>

/*
 * @brief function to initialize packet sniffer
 * @param interface - name of the network interface to sniff on (e.g., "eth0", "wlan0")
 * @param dst_ip - destination IP address to filter for (as a string)
 * @param src_port - source port number to filter for
 * @param dst_port - destination port number
 * @param verbose_flag - boolean flag to enable verbose output for debugging
 * @param protocol - IP protocol number (IPPROTO_TCP for TCP, IPPROTO_UDP for UDP)
 * @return pointer to pcap_t handle on success, NULL on failure
 */
pcap_t *init_sniffer(const char *interface, const char *dst_ip, int src_port, int dst_port, bool verbose_flag, int protocol);

/*
 * @brief function to start sniffing for packets
 * @param handle - pointer to pcap_t handle returned by init_sniffer
 * @param header - pointer to pointer to pcap_pkthdr struct to store packet header information
 * @param packet - pointer to pointer to unsigned char array to store packet data
 * @param timeout_ms - timeout in milliseconds to wait for a packet before returning
 * @param verbose_flag - boolean flag to enable verbose output for debugging
 * @return 1 if a packet was captured, 0 if timeout occurred, -1 on error
 */
int sniff_response(pcap_t *handle, struct pcap_pkthdr **header, const unsigned char **packet, int timeout_ms, bool verbose_flag);

#endif