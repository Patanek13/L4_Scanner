/*
 * @file sniffer.c
 * @author Patrik Lošťák <xlostap00>
 * @brief Implementation of packet sniffer functions to capture responses to our SYN packets
 */

#include "sniffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
extern pcap_t *global_handle; // Global handle for signal handler

#define EXPRSIZE 256 // max size of buffer for filter expr
#define MILISEC 1000 // num of ms in 1 sec
#define DELAY 10000 // num of microseconds

pcap_t *init_sniffer(const char *interface, const char *dst_ip, int src_port, int dst_port, bool verbose_flag, int protocol) {
    char err_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open NIC for sniffing
    handle = pcap_open_live(interface, BUFSIZ, 0, 1, err_buffer);
    if (handle == NULL) {
        fprintf(stderr, "ERROR: pcap_open_live failed\n");
        exit(1);
    }
    global_handle = handle; // Set global handle for signal handler

    // create text filter (same in wireshark)
    char filter_expr[EXPRSIZE];
    if (protocol == IPPROTO_TCP) {
        snprintf(filter_expr, sizeof(filter_expr), "src host %s and tcp dst port %d and tcp src port %d", dst_ip, src_port, dst_port);
    } else {
        snprintf(filter_expr, sizeof(filter_expr), "src host %s and (icmp or icmp6)", dst_ip);
    }
    
    // compile filter into binary
    struct bpf_program filter_prog;
    if (pcap_compile(handle, &filter_prog, filter_expr, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "ERROR: pcap_compile failed for filter '%s': %s\n", filter_expr, pcap_geterr(handle));
        exit(1);
    }

    // Use the filter on pcap handle
    if (pcap_setfilter(handle, &filter_prog) == -1) {
        fprintf(stderr, "ERROR: pcap_setfilter failed: %s\n", pcap_geterr(handle));
        exit(1);
    }
    pcap_freecode(&filter_prog);
    if (verbose_flag)
    fprintf(stderr, "Sniffer ready on interface %s. Waiting for response from %s to port %d\n", interface, dst_ip, src_port);

    return handle;
}

// Sniffer response, returns 1 if packet received, 0 if timeout, -1 on error
int sniff_response(pcap_t *handle, struct pcap_pkthdr **header, const unsigned char **packet, int timeout_ms, bool verbose_flag) {
    char err_buffer[PCAP_ERRBUF_SIZE];

    // Set pcap into non blocking mode
    if (pcap_setnonblock(handle, 1, err_buffer) == -1) {
        fprintf(stderr, "ERROR: pcap_setonblock failed: %s\n", pcap_geterr(handle));
        return -1;
    }

    // When we started
    struct timeval start, now;
    gettimeofday(&start, NULL);
    
    while (1) {
        int response = pcap_next_ex(handle, header, packet);

        if (response == 1) {
            if (verbose_flag)
            fprintf(stderr, "SNIFFER: Caught matching packet of size %d bytes\n", (*header)->len);
            return 1;
        } else if (response == -1 || response == -2) {
            fprintf(stderr, "ERROR: reading packet failed %s\n", pcap_geterr(handle));
            return -1;
        }

        // response 0 but packet didn't arrive, check for timeout
        gettimeofday(&now, NULL);
        long elapsed_time = (now.tv_sec - start.tv_sec) * MILISEC + (now.tv_usec - start.tv_usec) / MILISEC;

        if (elapsed_time >= timeout_ms) {
            if (verbose_flag)
            fprintf(stderr, "Timeout %d ms. No response\n", timeout_ms);
            return 0;
        }
        // prevent busy waiting
        usleep(DELAY);
    }
}
