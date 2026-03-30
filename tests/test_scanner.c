#include "unity/unity.h"
#include "../src/scanner.h"
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <string.h>

// Unity need these empty setup/teardown functions
void setUp(void) {}
void tearDown(void) {}

// ==========================================
// 1. TEST OF INTERFACE INDEX RETRIEVAL (if_nametoindex)
// ==========================================

void test_Interface_Loopback_ShouldExist(void) {
    // Loopback interface "lo" should always exist and return valid index (non-zero)
    unsigned int idx = if_nametoindex("lo");
    TEST_ASSERT_GREATER_THAN_MESSAGE(0, idx, "Interface 'lo' should exist and return valid index.");
}

void test_Interface_Invalid_ShouldReturnZero(void) {
    // No such interface should return index 0
    unsigned int idx = if_nametoindex("nonsense_eth99");
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, idx, "Invalid interface should return index 0.");
}

// ==========================================
// 2. TESTS OF IPv4 ADDRESS VALIDATION (inet_pton)
// ==========================================

void test_IPValidation_IPv4_Valid_ShouldPass(void) {
    struct sockaddr_in sa;
    // inet_pton returns 1 on success, so we check for that
    int result = inet_pton(AF_INET, "147.229.9.23", &(sa.sin_addr));
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, result, "Valid IPv4 address should be parsed successfully.");
}

void test_IPValidation_IPv4_Invalid_ShouldFail(void) {
    struct sockaddr_in sa;
    // Invalid format (too many octets or non-numeric characters) should return 0
    int result = inet_pton(AF_INET, "999.999.999.999", &(sa.sin_addr));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, result, "Out of range IPv4 address should fail.");
    result = inet_pton(AF_INET, "192.168.1.256", &(sa.sin_addr));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, result, "Octet value out of range should fail.");
    result = inet_pton(AF_INET, "192.168.1.-1", &(sa.sin_addr));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, result, "Negative octet value should fail.");
    
    // Invalid format (not enough octets) should return 0
    result = inet_pton(AF_INET, "192.168.1", &(sa.sin_addr));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, result, "Incomplete IPv4 address should fail.");
    result = inet_pton(AF_INET, "not_an_ip", &(sa.sin_addr));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, result, "Text string instead of IPv4 should fail.");
}

// ==========================================
// 3. TESTS OF IPv6 ADDRESS VALIDATION (inet_pton)
// ==========================================

void test_IPValidation_IPv6_Valid_ShouldPass(void) {
    struct sockaddr_in6 sa;
    int result = inet_pton(AF_INET6, "2001:67c:1220:809::93e5:917", &(sa.sin6_addr));
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, result, "Valid IPv6 address should be parsed successfully.");
}

void test_IPValidation_IPv6_Invalid_ShouldFail(void) {
    struct sockaddr_in6 sa;
    // Invalid format (too many hextets or non-hex characters) should return 0
    int result = inet_pton(AF_INET6, "2001:67c:1220:809::93e5:917:1234:856", &(sa.sin6_addr));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, result, "Too many hextets in IPv6 address should fail.");
    result = inet_pton(AF_INET6, "2001:67c:1220:809::93e5:917:zzzz", &(sa.sin6_addr));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, result, "Non-hex characters in IPv6 address should fail.");
    result = inet_pton(AF_INET6, "2001:67c:1220:809::93e5:917:12345", &(sa.sin6_addr));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, result, "Hextet value out of range should fail.");
    result = inet_pton(AF_INET6, "2001:67c:1220:809", &(sa.sin6_addr));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, result, "Too few hextets in IPv6 address should fail.");
    result = inet_pton(AF_INET6, "not_an_ip", &(sa.sin6_addr));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, result, "Text string instead of IPv6 should fail.");
    result = inet_pton(AF_INET6, "2001:xyz::93e5:917", &(sa.sin6_addr));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, result, "Invalid characters in IPv6 should fail.");
}

void test_IPValidation_IPv6_Valid_Compressed_ShouldPass(void) {
    struct sockaddr_in6 sa;
    // Valid compressed IPv6 address should be parsed successfully
    int result = inet_pton(AF_INET6, "2001:67c:1220:809::93e5:917", &(sa.sin6_addr));
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, result, "Valid compressed IPv6 address should be parsed successfully.");
}

void test_IPValidation_IPv6_Invalid_Compressed_ShouldFail(void) {
    struct sockaddr_in6 sa;
    // Invalid compressed format (multiple '::') should return 0
    int result = inet_pton(AF_INET6, "2001:67c::1220:809::93e5:917", &(sa.sin6_addr));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, result, "Multiple '::' in IPv6 address should fail.");
    result = inet_pton(AF_INET6, "::2001:67c:1220:809::93e5:917", &(sa.sin6_addr));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, result, "Leading '::' with multiple '::' should fail.");
    result = inet_pton(AF_INET6, "2001:67c:1220:809::93e5:917::", &(sa.sin6_addr));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, result, "Trailing '::' with multiple '::' should fail.");
}

// ==========================================
// 4. TESTS OF SCANNER HELPER FUNCTIONS
// ==========================================

void test_TCPHeader_Definition_ShouldSetExpectedFields(void) {
    struct tcphdr tcp_header;

    define_tcp_syn_header(&tcp_header, 12345, 80);

    TEST_ASSERT_EQUAL_UINT16_MESSAGE(htons(12345), tcp_header.source, "Source port should be encoded in network byte order.");
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(htons(80), tcp_header.dest, "Destination port should be encoded in network byte order.");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(htonl(1311), tcp_header.seq, "Sequence number should match scanner constant.");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0, tcp_header.ack_seq, "ACK sequence should be zero for SYN packet.");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(5, tcp_header.doff, "TCP header length should be 5 words.");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(1, tcp_header.syn, "SYN flag should be set.");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0, tcp_header.ack, "ACK flag should not be set.");
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(htons(65535), tcp_header.window, "Window size should match scanner constant.");
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(0, tcp_header.check, "Checksum should be zero before checksum calculation.");
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(0, tcp_header.urg_ptr, "Urgent pointer should be zero.");
}

void test_Checksum_AllZeros_ShouldBeFFFF(void) {
    uint16_t data[10] = {0};

    unsigned short checksum = calculate_checksum(data, (int)sizeof(data));

    TEST_ASSERT_EQUAL_HEX16_MESSAGE(0xFFFF, checksum, "Checksum of zeroed data should be 0xFFFF.");
}

void test_Checksum_OddLengthBuffer_ShouldBeDeterministic(void) {
    unsigned char payload[] = {0x01, 0x02, 0x03, 0x04, 0x05};

    unsigned short checksum_first = calculate_checksum(payload, (int)sizeof(payload));
    unsigned short checksum_second = calculate_checksum(payload, (int)sizeof(payload));

    TEST_ASSERT_EQUAL_HEX16_MESSAGE(checksum_first, checksum_second, "Checksum for the same odd-length payload should be stable.");
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, checksum_first, "Checksum should not be zero for this payload.");
}

void test_TCPChecksum_IPv4_ShouldBeStableAndNonZero(void) {
    struct tcphdr tcp_header_a;
    struct tcphdr tcp_header_b;

    define_tcp_syn_header(&tcp_header_a, 40000, 443);
    define_tcp_syn_header(&tcp_header_b, 40000, 443);

    calculate_tcp_hdr_checksum_ipv4(&tcp_header_a, "127.0.0.1", "127.0.0.1");
    calculate_tcp_hdr_checksum_ipv4(&tcp_header_b, "127.0.0.1", "127.0.0.1");

    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, tcp_header_a.check, "IPv4 TCP checksum should be populated.");
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(tcp_header_a.check, tcp_header_b.check, "IPv4 checksum should be deterministic for identical inputs.");
}

void test_TCPChecksum_IPv6_ShouldBeStableAndNonZero(void) {
    struct tcphdr tcp_header_a;
    struct tcphdr tcp_header_b;

    define_tcp_syn_header(&tcp_header_a, 40001, 443);
    define_tcp_syn_header(&tcp_header_b, 40001, 443);

    calculate_tcp_hdr_checksum_ipv6(&tcp_header_a, "::1", "::1");
    calculate_tcp_hdr_checksum_ipv6(&tcp_header_b, "::1", "::1");

    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, tcp_header_a.check, "IPv6 TCP checksum should be populated.");
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(tcp_header_a.check, tcp_header_b.check, "IPv6 checksum should be deterministic for identical inputs.");
}

void test_GetSrcIP_IPv4_Loopback_ShouldReturnValidAddress(void) {
    char src_ip[INET_ADDRSTRLEN] = {0};

    int result = get_src_ip(AF_INET, "127.0.0.1", src_ip, sizeof(src_ip));
    struct sockaddr_in parsed;
    int parse_result = inet_pton(AF_INET, src_ip, &parsed.sin_addr);

    TEST_ASSERT_EQUAL_INT_MESSAGE(0, result, "get_src_ip should succeed for IPv4 loopback destination.");
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, parse_result, "Returned source IPv4 should be parseable by inet_pton.");
}

void test_GetSrcIP_IPv6_Loopback_ShouldReturnValidAddress(void) {
    char src_ip[INET6_ADDRSTRLEN] = {0};

    int result = get_src_ip(AF_INET6, "::1", src_ip, sizeof(src_ip));
    struct sockaddr_in6 parsed;
    int parse_result = inet_pton(AF_INET6, src_ip, &parsed.sin6_addr);

    TEST_ASSERT_EQUAL_INT_MESSAGE(0, result, "get_src_ip should succeed for IPv6 loopback destination.");
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, parse_result, "Returned source IPv6 should be parseable by inet_pton.");
}



// ==========================================
// MAIN FUNCTION TO RUN ALL TESTS
// ==========================================
int main(void) {
    UNITY_BEGIN();

    // Execute interface tests
    RUN_TEST(test_Interface_Loopback_ShouldExist);
    RUN_TEST(test_Interface_Invalid_ShouldReturnZero);

    // Execute IPv4 address validation tests
    RUN_TEST(test_IPValidation_IPv4_Valid_ShouldPass);
    RUN_TEST(test_IPValidation_IPv4_Invalid_ShouldFail);

    // Execute IPv6 address validation tests
    RUN_TEST(test_IPValidation_IPv6_Valid_ShouldPass);
    RUN_TEST(test_IPValidation_IPv6_Invalid_ShouldFail);
    RUN_TEST(test_IPValidation_IPv6_Valid_Compressed_ShouldPass);
    RUN_TEST(test_IPValidation_IPv6_Invalid_Compressed_ShouldFail);

    // Execute scanner helper tests
    RUN_TEST(test_TCPHeader_Definition_ShouldSetExpectedFields);
    RUN_TEST(test_Checksum_AllZeros_ShouldBeFFFF);
    RUN_TEST(test_Checksum_OddLengthBuffer_ShouldBeDeterministic);
    RUN_TEST(test_TCPChecksum_IPv4_ShouldBeStableAndNonZero);
    RUN_TEST(test_TCPChecksum_IPv6_ShouldBeStableAndNonZero);
    RUN_TEST(test_GetSrcIP_IPv4_Loopback_ShouldReturnValidAddress);
    RUN_TEST(test_GetSrcIP_IPv6_Loopback_ShouldReturnValidAddress);

    return UNITY_END();
}