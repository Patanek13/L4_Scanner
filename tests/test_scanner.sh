#!/bin/bash

# ==============================================
#  L4 SCANNER - AUTOMATED INTEGRATION TEST SUITE
# ==============================================

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASSED=0
FAILED=0
TOTAL=0

# Find executable path
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
BIN="$SCRIPT_DIR/../ipk-L4-scan"

echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}   STARTING INTEGRATION TEST SUITE        ${NC}"
echo -e "${BLUE}==========================================${NC}\n"

# ------------------------------------------
# HELPER FUNCTIONS
# ------------------------------------------

# Function to run a test case
run_test() {
    local test_name="$1"
    local expected_grep="$2"
    local command_to_run="$3"
    local expect_fail="$4" # 1 = expected to fail, 0 = expected to pass

    ((TOTAL++))
    
    OUTPUT=$(eval "$command_to_run" 2>&1)
    EXIT_CODE=$?

    local IS_PASS=0

    if [ "$expect_fail" == "1" ]; then
        if [ $EXIT_CODE -ne 0 ]; then IS_PASS=1; fi
    else
        if echo "$OUTPUT" | grep -qE "$expected_grep"; then IS_PASS=1; fi
    fi

    if [ $IS_PASS -eq 1 ]; then
        echo -e "[ ${GREEN}PASS${NC} ] $test_name"
        ((PASSED++))
    else
        echo -e "[ ${RED}FAIL${NC} ] $test_name"
        echo -e "       ${YELLOW}Command:${NC} $command_to_run"
        echo -e "       ${YELLOW}Output:${NC} $OUTPUT"
        ((FAILED++))
    fi
}

# ------------------------------------------
# SETUP - Start mock servers
# ------------------------------------------
echo -e "${YELLOW}>> Setting up local mock servers...${NC}"

# TCP servers (open ports 55001, 55005)
(while true; do nc -l -p 55001 >/dev/null 2>&1; done) & PID_TCP4_1=$!
(while true; do nc -l -p 55005 >/dev/null 2>&1; done) & PID_TCP4_2=$!

# UDP servers (open ports 55002, 55006)
(while true; do nc -u -l 55002 >/dev/null 2>&1; done) & PID_UDP4_1=$!
(while true; do nc -u -l 55006 >/dev/null 2>&1; done) & PID_UDP4_2=$!

# IPv6 TCP servers (open ports 56001, 56005)
(while true; do nc -6 -l 56001 >/dev/null 2>&1; done) & PID_TCP6_1=$!
(while true; do nc -6 -l 56005 >/dev/null 2>&1; done) & PID_TCP6_2=$!

# IPv6 UDP servers (open ports 56002, 56006)
(while true; do nc -6 -u -l 56002 >/dev/null 2>&1; done) & PID_UDP6_1=$!
(while true; do nc -6 -u -l 56006 >/dev/null 2>&1; done) & PID_UDP6_2=$!

sleep 1 # Wait a moment for servers to start

# ------------------------------------------
# START TESTS
# ------------------------------------------

# BASIC TESTS
run_test "test_compilation_make" "" "make -C \"$SCRIPT_DIR/..\" >/dev/null" 0
run_test "test_arg_interface" "" "$BIN -t 80 localhost >/dev/null" 1
run_test "test_arg_help" "" "$BIN -h >/dev/null" 0
run_test "test_arg_help_long" "" "$BIN --help >/dev/null" 0
run_test "test_dns_invalid" "" "$BIN -i lo -t 80 invalid.domain.xyz >/dev/null" 1

# CLI ARGUMENT VALIDATION TESTS
run_test "test_arg_no_arguments" "" "$BIN >/dev/null" 1
run_test "test_arg_only_host_no_flags" "" "$BIN 127.0.0.1 >/dev/null" 1
run_test "test_arg_interface_list_only" "" "$BIN -i >/dev/null" 0
run_test "test_arg_missing_interface" "" "$BIN -t 80 127.0.0.1 >/dev/null" 1
run_test "test_arg_invalid_interface" "" "$BIN -i definitely-not-an-iface -t 80 127.0.0.1 >/dev/null" 1
run_test "test_arg_missing_host" "" "$BIN -i lo -t 80 >/dev/null" 1
run_test "test_arg_unknown_option" "" "$BIN -x 2>/dev/null" 1
run_test "test_arg_unknown_long_option" "" "$BIN --no-such-option 2>/dev/null" 1
run_test "test_arg_missing_timeout_value" "" "$BIN -i lo -t 80 -w >/dev/null" 1
run_test "test_arg_timeout_nonnumeric" "" "$BIN -i lo -t 80 -w abc 127.0.0.1 >/dev/null" 1
run_test "test_arg_timeout_with_plus" "" "$BIN -i lo -t 80 -w +5 127.0.0.1 >/dev/null" 1
run_test "test_arg_timeout_negative" "" "$BIN -i lo -t 80 -w -5 127.0.0.1 >/dev/null" 1
run_test "test_arg_timeout_empty" "" "$BIN -i lo -t 80 -w '' 127.0.0.1 >/dev/null" 1
run_test "test_arg_tcp_port_zero" "" "$BIN -i lo -t 0 127.0.0.1 >/dev/null" 1
run_test "test_arg_tcp_port_too_high" "" "$BIN -i lo -t 70000 127.0.0.1 >/dev/null" 1
run_test "test_arg_tcp_port_nonnumeric" "" "$BIN -i lo -t 443abc 127.0.0.1 >/dev/null" 1
run_test "test_arg_tcp_bad_range_desc" "" "$BIN -i lo -t 100-10 127.0.0.1 >/dev/null" 1
run_test "test_arg_tcp_range_out_of_bounds" "" "$BIN -i lo -t 65535-65536 127.0.0.1 >/dev/null" 1
run_test "test_arg_udp_port_zero" "" "$BIN -i lo -u 0 127.0.0.1 >/dev/null" 1
run_test "test_arg_udp_port_too_high" "" "$BIN -i lo -u 70000 127.0.0.1 >/dev/null" 1
run_test "test_arg_udp_bad_range_desc" "" "$BIN -i lo -u 100-10 127.0.0.1 >/dev/null" 1
run_test "test_arg_udp_range_out_of_bounds" "" "$BIN -i lo -u 65535-65536 127.0.0.1 >/dev/null" 1
run_test "test_arg_no_ports_selected" "" "$BIN -i lo 127.0.0.1 >/dev/null" 0
run_test "test_arg_verbose_no_ports" "" "$BIN -v -i lo 127.0.0.1 >/dev/null" 0
run_test "test_arg_double_interface_same" "" "$BIN -i lo -i lo 127.0.0.1 >/dev/null" 0
run_test "test_arg_double_interface_last_invalid" "" "$BIN -i lo -i definitely-not-an-iface 127.0.0.1 >/dev/null" 1
run_test "test_arg_double_interface_last_valid" "" "$BIN -i definitely-not-an-iface -i lo 127.0.0.1 >/dev/null" 0
run_test "test_arg_double_timeout" "" "$BIN -i lo -w 10 -w 20 127.0.0.1 >/dev/null" 0
run_test "test_arg_positional_after_double_dash" "" "$BIN -i lo -- 127.0.0.1 >/dev/null" 0
run_test "test_arg_host_before_flags" "" "$BIN 127.0.0.1 -i lo >/dev/null" 0
run_test "test_arg_extra_positional_ignored" "" "$BIN -i lo 127.0.0.1 extra-arg >/dev/null" 0

# TCP - IPv4
run_test "test_lan1[IPv4-single open TCP port]" "55001 tcp open" "sudo $BIN -i lo -t 55001 127.0.0.1" 0
run_test "test_lan2[IPv4-single closed TCP port]" "55010 tcp closed" "sudo $BIN -i lo -t 55010 127.0.0.1" 0
run_test "test_lan3[IPv4-sequence of 2 closed TCP ports]" "closed.*closed" "sudo $BIN -i lo -t 55010,55011 127.0.0.1 | tr '\n' ' '" 0
run_test "test_lan4[IPv4-sequence of 2 open TCP ports]" "open.*open" "sudo $BIN -i lo -t 55001,55005 127.0.0.1 | sort | tr '\n' ' '" 0
run_test "test_lan5[IPv4-sequence of 2 open and closed TCP ports]" "open.*closed" "sudo $BIN -i lo -t 55001,55010 127.0.0.1 | sort | tr '\n' ' '" 0
run_test "test_lan6[IPv4-range of 3 open and closed TCP ports]" "closed.*open.*closed" "sudo $BIN -i lo -t 55000-55002 127.0.0.1 | sort | tr '\n' ' '" 0

# UDP - IPv4
run_test "test_lan7[IPv4-single open UDP port]" "55002 udp open" "sudo $BIN -i lo -u 55002 127.0.0.1" 0
run_test "test_lan8[IPv4-single closed UDP port]" "55012 udp closed" "sudo $BIN -i lo -u 55012 127.0.0.1" 0
run_test "test_lan9[IPv4-sequence of 2 closed UDP ports]" "closed.*closed" "sudo $BIN -i lo -u 55012,55013 127.0.0.1 | tr '\n' ' '" 0
run_test "test_lan10[IPv4-sequence of 2 open UDP ports]" "open.*open" "sudo $BIN -i lo -u 55002,55006 127.0.0.1 | sort | tr '\n' ' '" 0
run_test "test_lan11[IPv4-sequence of 2 open and closed UDP ports]" "open.*closed" "sudo $BIN -i lo -u 55002,55012 127.0.0.1 | sort | tr '\n' ' '" 0
run_test "test_lan12[IPv4-range of 3 open and closed UDP ports]" "closed.*open.*closed" "sudo $BIN -i lo -u 55001-55003 127.0.0.1 | sort | tr '\n' ' '" 0

# COMBINED (TCP and UDP)
run_test "test_lan13[IPv4-range of 3 TCP, sequence of 2 UDP]" "tcp.*udp" "sudo $BIN -i lo -t 55000-55002 -u 55002,55012 127.0.0.1 | sort | tr '\n' ' '" 0

# TCP - IPv6
run_test "test_lan15[IPv6-single open TCP port]" "56001 tcp open" "sudo $BIN -i lo -t 56001 ::1" 0
run_test "test_lan16[IPv6-single closed TCP port]" "56010 tcp closed" "sudo $BIN -i lo -t 56010 ::1" 0
run_test "test_lan17[IPv6-sequence of 2 open TCP ports]" "open.*open" "sudo $BIN -i lo -t 56001,56005 ::1 | sort | tr '\n' ' '" 0

# UDP - IPv6
run_test "test_lan18[IPv6-single open UDP port]" "56002 udp open" "sudo $BIN -i lo -u 56002 ::1" 0
run_test "test_lan19[IPv6-single closed UDP port]" "56012 udp closed" "sudo $BIN -i lo -u 56012 ::1" 0
run_test "test_lan20[IPv6-sequence of 2 open UDP ports]" "open.*open" "sudo $BIN -i lo -u 56002,56006 ::1 | sort | tr '\n' ' '" 0

# COMBINED - IPv6
run_test "test_lan21[IPv6-range of 3 TCP, sequence of 2 UDP]" "tcp.*udp" "sudo $BIN -i lo -t 56000-56002 -u 56002,56012 ::1 | sort | tr '\n' ' '" 0

# DNS AAAA
run_test "test_dns_aaaa_loopback" "tcp" "sudo $BIN -i lo -t 56001 localhost" 0

# DNS A ALISASES 
run_test "test_tcp1[127.0.0.1 single open TCP port]" "55001 tcp open" "sudo $BIN -i lo -t 55001 127.0.0.1" 0
run_test "test_tcp2[localhost single open TCP port]" "55001 tcp open" "sudo $BIN -i lo -t 55001 localhost" 0
run_test "test_dns_a_aaaa_multiple" "tcp" "sudo $BIN -i lo -t 55001 localhost" 0
run_test "test_dns_a_aaaa_single" "tcp" "sudo $BIN -i lo -t 55001 127.0.0.1" 0

# TIMETOUT TESTS (check that we can handle timeouts properly and they don't cause crashes or hangs)
run_test "test_timeout_short" "tcp" "sudo $BIN -i lo -t 55010 -w 5 127.0.0.1" 0
run_test "test_timeout_long" "tcp" "sudo $BIN -i lo -t 55010 -w 2000 127.0.0.1" 0

# HANDSHAKE tests (check that we can complete TCP handshake on open port and fail on closed port)
run_test "test_lan_tcp_handshake_allowed" "tcp" "sudo $BIN -i lo -t 55001 127.0.0.1" 0
run_test "test_lan_tcp_handshake_allowed_short_port_arg" "tcp" "sudo $BIN -i lo -t 80 127.0.0.1" 0

# ------------------------------------------
# 3. CLEANUP - Stop mock servers
# ------------------------------------------
kill $PID_TCP4_1 $PID_TCP4_2 $PID_UDP4_1 $PID_UDP4_2 $PID_TCP6_1 $PID_TCP6_2 $PID_UDP6_1 $PID_UDP6_2 >/dev/null 2>&1
wait $PID_TCP4_1 $PID_TCP4_2 $PID_UDP4_1 $PID_UDP4_2 $PID_TCP6_1 $PID_TCP6_2 $PID_UDP6_1 $PID_UDP6_2 >/dev/null 2>&1


# ------------------------------------------
# 4. SUMMARY
# ------------------------------------------
echo -e "\n${BLUE}==========================================${NC}"
echo -e "${BLUE}   TEST SUMMARY                           ${NC}"
echo -e "${BLUE}==========================================${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "   ${GREEN}All $TOTAL tests passed! ${NC} ✅"
else
    echo -e "   ${GREEN}Passed: $PASSED${NC}"
    echo -e "   ${RED}Failed: $FAILED${NC}"
    echo -e "   ${YELLOW}Total:  $TOTAL${NC}"
    echo -e "\n${RED}Some tests failed.${NC} ❌"
    exit 1
fi

echo -e "${BLUE}==========================================${NC}\n"
exit 0