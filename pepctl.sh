#!/bin/bash
# RFC 3135 PEP TCP Accelerator v2.0 - Control Script
# ===================================================
# Usage: ./pepctl.sh [command]
#
# Commands:
#   status      - Show module status and statistics
#   flows       - Show active flow table
#   config      - Show current configuration
#   learning    - Show Q-Learning congestion control statistics (NEW v2.0)
#   regions     - Show Regional Learning statistics (NEW v2.0)
#   debug on    - Enable debug logging (level 3)
#   debug off   - Disable debug logging (level 0)
#   debug N     - Set debug level to N (0-4)
#   watch       - Continuously monitor stats (Ctrl+C to stop)
#   watchall    - Monitor all stats including learning (Ctrl+C to stop)
#   log         - Show recent kernel log messages
#   help        - Show this help message

# Configuration
MODULE_NAME="pep_accelerator"
PROC_BASE="/proc/pep"
SYSFS_PARAM="/sys/module/${MODULE_NAME}/parameters"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Check if module is loaded
check_module() {
    if ! lsmod | grep -q "^${MODULE_NAME}"; then
        echo -e "${RED}[ERROR]${NC} Module ${MODULE_NAME} is not loaded"
        echo "Run './loadconfig.sh' to load the module"
        exit 1
    fi
}

# Helper: Get sysfs parameter value
get_param() {
    local name="$1"
    local default="${2:-N/A}"
    if [ -f "${SYSFS_PARAM}/${name}" ]; then
        cat "${SYSFS_PARAM}/${name}" 2>/dev/null || echo "$default"
    else
        echo "$default"
    fi
}

# Show module status and statistics
show_status() {
    check_module

    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║        PEP TCP Accelerator v2.0 - Status                 ║${NC}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Basic module info
    echo -e "${BOLD}Module Information:${NC}"
    echo -n "  Status: "
    if [ -d "$PROC_BASE" ]; then
        echo -e "${GREEN}Running${NC}"
    else
        echo -e "${RED}Not Running${NC}"
    fi

    # Memory usage from lsmod
    local mem=$(lsmod | grep "^${MODULE_NAME}" | awk '{print $2}')
    echo "  Memory: ${mem} bytes"
    echo ""

    # Show statistics from proc
    if [ -f "${PROC_BASE}/stats" ]; then
        echo -e "${BOLD}Statistics:${NC}"
        cat "${PROC_BASE}/stats" | while read line; do
            echo "  $line"
        done
        echo ""
    fi

    # Key settings organized by category
    echo -e "${BOLD}=== Core Settings ===${NC}"
    printf "  %-20s: %s\n" "enabled" "$(get_param enabled)"
    printf "  %-20s: %s\n" "max_flows" "$(get_param max_flows)"
    printf "  %-20s: %s ms\n" "flow_timeout" "$(get_param flow_timeout)"
    echo ""

    echo -e "${BOLD}=== Split-TCP Settings ===${NC}"
    printf "  %-20s: %s\n" "tcp_spoofing" "$(get_param tcp_spoofing)"
    printf "  %-20s: %s\n" "fake_ack" "$(get_param fake_ack)"
    printf "  %-20s: %s\n" "local_retrans" "$(get_param local_retrans)"
    echo ""

    echo -e "${BOLD}=== Congestion Control ===${NC}"
    printf "  %-20s: %s segments\n" "init_cwnd" "$(get_param init_cwnd)"
    printf "  %-20s: %s Mbps\n" "bandwidth_mbps" "$(get_param bandwidth_mbps)"
    printf "  %-20s: %s\n" "learning_enabled" "$(get_param learning_enabled)"
    echo ""

    echo -e "${BOLD}=== ACK Pacing (v2.0) ===${NC}"
    printf "  %-20s: %s\n" "ack_pacing" "$(get_param ack_pacing)"
    printf "  %-20s: %s us\n" "ack_delay_us" "$(get_param ack_delay_us)"
    printf "  %-20s: %s bytes\n" "ack_bytes_threshold" "$(get_param ack_bytes_threshold)"
    echo ""

    echo -e "${BOLD}=== Regional Learning (v2.0) ===${NC}"
    printf "  %-20s: %s\n" "region_learning" "$(get_param region_learning)"
    printf "  %-20s: %s\n" "region_max" "$(get_param region_max)"
    printf "  %-20s: /%s\n" "region_prefix" "$(get_param region_prefix)"
    echo ""

    echo -e "${BOLD}=== Debug ===${NC}"
    local debug_level=$(get_param debug_level)
    printf "  %-20s: %s" "debug_level" "$debug_level"
    case "$debug_level" in
        0) echo " (OFF)" ;;
        1) echo " (ERROR)" ;;
        2) echo " (WARN)" ;;
        3) echo " (INFO)" ;;
        4) echo " (DEBUG)" ;;
        *) echo "" ;;
    esac
}

# Show active flows
show_flows() {
    check_module

    echo -e "${BOLD}${CYAN}=== Active Flows ===${NC}"
    echo ""

    if [ -f "${PROC_BASE}/flows" ]; then
        local flow_count=$(wc -l < "${PROC_BASE}/flows")
        echo -e "Total flows: ${GREEN}${flow_count}${NC}"
        echo ""
        cat "${PROC_BASE}/flows"
    else
        echo "Flow information not available"
    fi
}

# Show full configuration
show_config() {
    check_module

    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║        PEP TCP Accelerator v2.0 - Configuration          ║${NC}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""

    if [ -f "${PROC_BASE}/config" ]; then
        echo -e "${BOLD}Configuration from /proc/pep/config:${NC}"
        cat "${PROC_BASE}/config"
    else
        echo "Configuration not available from proc"
    fi

    echo ""
    echo -e "${BOLD}Module Parameters (sysfs):${NC}"
    if [ -d "$SYSFS_PARAM" ]; then
        echo ""
        echo "  === Basic ==="
        for p in enabled max_flows flow_timeout; do
            printf "    %-25s = %s\n" "$p" "$(get_param $p)"
        done

        echo ""
        echo "  === Queue ==="
        for p in lan_wan_queue_min lan_wan_queue_max wan_lan_queue_min wan_lan_queue_max; do
            printf "    %-25s = %s\n" "$p" "$(get_param $p)"
        done

        echo ""
        echo "  === RTO/CC ==="
        for p in rto_min rto_max init_cwnd bandwidth_mbps; do
            printf "    %-25s = %s\n" "$p" "$(get_param $p)"
        done

        echo ""
        echo "  === Features ==="
        for p in tcp_spoofing fake_ack local_retrans gso_enabled gro_enabled learning_enabled; do
            printf "    %-25s = %s\n" "$p" "$(get_param $p)"
        done

        echo ""
        echo "  === ACK Pacing (v2.0) ==="
        for p in ack_pacing ack_delay_us ack_bytes_threshold; do
            printf "    %-25s = %s\n" "$p" "$(get_param $p)"
        done

        echo ""
        echo "  === Regional Learning (v2.0) ==="
        for p in region_learning region_max region_prefix; do
            printf "    %-25s = %s\n" "$p" "$(get_param $p)"
        done

        echo ""
        echo "  === Debug ==="
        printf "    %-25s = %s\n" "debug_level" "$(get_param debug_level)"
    else
        echo "  Sysfs parameters not available"
    fi
}

# Show Q-Learning statistics
show_learning() {
    check_module

    echo -e "${BOLD}${MAGENTA}=== Self-Learning Congestion Control (Q-Learning) ===${NC}"
    echo ""

    local learning_enabled=$(get_param learning_enabled)
    if [ "$learning_enabled" != "1" ]; then
        echo -e "${YELLOW}[WARN]${NC} Self-Learning CC is disabled (learning_enabled=0)"
        echo "Enable with: echo 1 > ${SYSFS_PARAM}/learning_enabled"
        echo ""
    fi

    if [ -f "${PROC_BASE}/learning" ]; then
        echo -e "${BOLD}Q-Learning Statistics:${NC}"
        cat "${PROC_BASE}/learning" | while read line; do
            echo "  $line"
        done
    else
        echo "Learning statistics not available"
        echo "(May require learning_enabled=1 in module parameters)"
    fi

    echo ""
    echo -e "${BOLD}Learning Parameters:${NC}"
    echo "  Algorithm:     Q-Learning with epsilon-greedy"
    echo "  States:        243 (3^5 discretized features)"
    echo "  Actions:       5 (CWND adjustments)"
    echo "  Alpha (LR):    0.1"
    echo "  Gamma:         0.9"
    echo "  Epsilon:       0.05"
}

# Show Regional Learning statistics
show_regions() {
    check_module

    echo -e "${BOLD}${MAGENTA}=== Regional Learning (Per-Destination Optimization) ===${NC}"
    echo ""

    local region_learning=$(get_param region_learning)
    if [ "$region_learning" != "1" ]; then
        echo -e "${YELLOW}[WARN]${NC} Regional Learning is disabled (region_learning=0)"
        echo "Enable with: echo 1 > ${SYSFS_PARAM}/region_learning"
        echo ""
    fi

    if [ -f "${PROC_BASE}/regions" ]; then
        echo -e "${BOLD}Regional Statistics:${NC}"
        cat "${PROC_BASE}/regions" | while read line; do
            echo "  $line"
        done
    else
        echo "Regional statistics not available"
        echo "(May require region_learning=1 in module parameters)"
    fi

    echo ""
    echo -e "${BOLD}Region Configuration:${NC}"
    printf "  %-20s: %s\n" "region_max" "$(get_param region_max)"
    printf "  %-20s: /%s (aggregate by C-class)\n" "region_prefix" "$(get_param region_prefix)"
    echo ""
    echo -e "${BOLD}How it works:${NC}"
    echo "  1. New flows inherit optimal parameters from historical data"
    echo "  2. Parameters tracked: init_cwnd, ssthresh, rto_min, ack_interval"
    echo "  3. Network characteristics: base_rtt, avg_rtt, bandwidth, loss_rate"
    echo "  4. Updated on flow completion using EWMA"
}

# Set debug level
set_debug() {
    local level="$1"

    case "$level" in
        on|ON)
            level=3
            ;;
        off|OFF)
            level=0
            ;;
        [0-4])
            # Valid numeric level
            ;;
        *)
            echo -e "${RED}[ERROR]${NC} Invalid debug level: $level"
            echo "Valid values: on, off, 0, 1, 2, 3, 4"
            exit 1
            ;;
    esac

    check_module

    if [ -f "${SYSFS_PARAM}/debug_level" ]; then
        echo "$level" > "${SYSFS_PARAM}/debug_level"
        echo -e "${GREEN}[OK]${NC} Debug level set to: $level"

        case "$level" in
            0) echo "  Level 0: Debug OFF (silent)" ;;
            1) echo "  Level 1: Errors only" ;;
            2) echo "  Level 2: Errors + Warnings" ;;
            3) echo "  Level 3: Errors + Warnings + Info" ;;
            4) echo "  Level 4: Verbose (all messages)" ;;
        esac
    else
        echo -e "${RED}[ERROR]${NC} Cannot write to sysfs parameter"
        echo "Are you running as root?"
        exit 1
    fi
}

# Watch mode - continuous monitoring
watch_stats() {
    check_module

    echo -e "${BOLD}${CYAN}=== PEP Monitor (Ctrl+C to stop) ===${NC}"
    echo ""

    while true; do
        clear
        echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BOLD}${CYAN}║        PEP TCP Accelerator v2.0 - Live Monitor           ║${NC}"
        echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
        echo "$(date '+%Y-%m-%d %H:%M:%S')"
        echo ""

        if [ -f "${PROC_BASE}/stats" ]; then
            echo -e "${BOLD}Statistics:${NC}"
            cat "${PROC_BASE}/stats" | while read line; do
                echo "  $line"
            done
        fi

        echo ""
        echo -e "${BOLD}Key Features:${NC}"
        printf "  tcp_spoofing=%-3s  fake_ack=%-3s  local_retrans=%-3s\n" \
               "$(get_param tcp_spoofing)" "$(get_param fake_ack)" "$(get_param local_retrans)"
        printf "  ack_pacing=%-5s  region_learning=%-3s  learning_enabled=%-3s\n" \
               "$(get_param ack_pacing)" "$(get_param region_learning)" "$(get_param learning_enabled)"

        echo ""
        echo -e "${YELLOW}Press Ctrl+C to stop${NC}"

        sleep 1
    done
}

# Watch all - including learning stats
watch_all() {
    check_module

    echo -e "${BOLD}${CYAN}=== PEP Full Monitor (Ctrl+C to stop) ===${NC}"
    echo ""

    while true; do
        clear
        echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BOLD}${CYAN}║      PEP TCP Accelerator v2.0 - Full Live Monitor        ║${NC}"
        echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
        echo "$(date '+%Y-%m-%d %H:%M:%S')"
        echo ""

        # Statistics
        if [ -f "${PROC_BASE}/stats" ]; then
            echo -e "${BOLD}=== Statistics ===${NC}"
            cat "${PROC_BASE}/stats" | head -10 | while read line; do
                echo "  $line"
            done
        fi

        # Learning stats (if available)
        if [ -f "${PROC_BASE}/learning" ]; then
            echo ""
            echo -e "${BOLD}=== Q-Learning ===${NC}"
            cat "${PROC_BASE}/learning" | head -5 | while read line; do
                echo "  $line"
            done
        fi

        # Regional stats (if available)
        if [ -f "${PROC_BASE}/regions" ]; then
            echo ""
            echo -e "${BOLD}=== Regional Learning ===${NC}"
            cat "${PROC_BASE}/regions" | head -5 | while read line; do
                echo "  $line"
            done
        fi

        echo ""
        echo -e "${YELLOW}Press Ctrl+C to stop${NC}"

        sleep 2
    done
}

# Show kernel log (dmesg) for PEP
show_log() {
    echo -e "${BOLD}${CYAN}=== PEP Kernel Log (last 50 lines) ===${NC}"
    echo ""
    dmesg | grep -i "pep:" | tail -50
}

# Show help
show_help() {
    echo -e "${BOLD}RFC 3135 PEP TCP Accelerator v2.0 - Control Script${NC}"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo -e "${BOLD}Commands:${NC}"
    echo "  status          Show module status and statistics"
    echo "  flows           Show active flow table"
    echo "  config          Show current configuration (all parameters)"
    echo ""
    echo -e "${BOLD}New in v2.0:${NC}"
    echo "  learning        Show Q-Learning congestion control statistics"
    echo "  regions         Show Regional Learning statistics"
    echo "  watchall        Monitor all stats including learning"
    echo ""
    echo -e "${BOLD}Debug:${NC}"
    echo "  debug on        Enable debug logging (level 3)"
    echo "  debug off       Disable debug logging (level 0)"
    echo "  debug N         Set debug level (0=off, 1=error, 2=warn, 3=info, 4=debug)"
    echo ""
    echo -e "${BOLD}Monitoring:${NC}"
    echo "  watch           Continuously monitor stats (Ctrl+C to stop)"
    echo "  watchall        Monitor all stats including learning (Ctrl+C to stop)"
    echo "  log             Show recent kernel log messages"
    echo ""
    echo -e "${BOLD}Other:${NC}"
    echo "  help            Show this help message"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  $0 status       # Check current status"
    echo "  $0 learning     # View Q-Learning statistics"
    echo "  $0 regions      # View Regional Learning cache"
    echo "  $0 debug on     # Enable debug messages"
    echo "  $0 watch        # Live monitoring"
    echo ""
    echo -e "${BOLD}v2.0 Features:${NC}"
    echo "  - ACK Pacing: Smooth Fake ACK transmission to prevent burst sending"
    echo "  - Regional Learning: Per-destination network optimization"
    echo "  - RACK/TLP: Time-based loss detection and tail loss probing"
    echo "  - High-Performance Checksum: Hardware offload (CHECKSUM_PARTIAL)"
}

# Main
case "${1:-status}" in
    status)
        show_status
        ;;
    flows)
        show_flows
        ;;
    config)
        show_config
        ;;
    learning)
        show_learning
        ;;
    regions)
        show_regions
        ;;
    debug)
        if [ -z "$2" ]; then
            echo -e "${RED}[ERROR]${NC} Missing argument for debug command"
            echo "Usage: $0 debug [on|off|0-4]"
            exit 1
        fi
        set_debug "$2"
        ;;
    watch)
        watch_stats
        ;;
    watchall)
        watch_all
        ;;
    log)
        show_log
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo -e "${RED}[ERROR]${NC} Unknown command: $1"
        show_help
        exit 1
        ;;
esac
