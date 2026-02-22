#!/bin/bash
# RFC 3135 PEP TCP Accelerator v2.0 - Module Loader Script
# =========================================================
# This script loads pep.conf and (re)loads the kernel module with new parameters
#
# Supports all v2.0 features:
# - ACK Pacing (ack_pacing, ack_delay_us, ack_bytes_threshold)
# - Regional Learning (region_learning, region_max, region_prefix)
# - Self-Learning CC (learning_enabled)
# - BDP-Aware Queue (queue_bdp_enabled, queue_bdp_multiplier, queue_max_absolute) [v24]
# - WAN RTT Fallback (wan_rtt_ms) [v25]

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/pep.conf"
MODULE_NAME="pep_accelerator"
MODULE_PATH="${SCRIPT_DIR}/${MODULE_NAME}.ko"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# System optimization for TCP performance
configure_system() {
    echo -e "${CYAN}[SYSTEM]${NC} Applying TCP optimizations..."

    # Enable TCP window scaling
    sysctl -w net.ipv4.tcp_window_scaling=1 > /dev/null 2>&1 || true

    # Increase buffer sizes
    sysctl -w net.core.rmem_max=8388608 > /dev/null 2>&1 || true
    sysctl -w net.core.wmem_max=8388608 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_rmem="4096 87380 8388608" > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_wmem="4096 16384 8388608" > /dev/null 2>&1 || true

    # Flush routing cache
    sysctl -w net.ipv4.route.flush=1 > /dev/null 2>&1 || true

    # v109: RPS/RFS — distribute softirq across all CPUs
    local ncpus=$(nproc 2>/dev/null || echo 2)
    local rps_mask=$(printf '%x' $(( (1 << ncpus) - 1 )))
    local wan_if="${WAN_IF:-enp0s5}"

    for rxq in /sys/class/net/${wan_if}/queues/rx-*/rps_cpus; do
        [ -f "$rxq" ] && echo "$rps_mask" > "$rxq" 2>/dev/null || true
    done

    # RFS flow entries (4096 per queue is reasonable)
    local rfs_total=$((4096 * ncpus))
    sysctl -w net.core.rps_sock_flow_entries=${rfs_total} > /dev/null 2>&1 || true
    for rxq in /sys/class/net/${wan_if}/queues/rx-*/rps_flow_cnt; do
        [ -f "$rxq" ] && echo 4096 > "$rxq" 2>/dev/null || true
    done

    # Increase netdev budget for high packet rate
    sysctl -w net.core.netdev_budget=600 > /dev/null 2>&1 || true
    sysctl -w net.core.netdev_budget_usecs=8000 > /dev/null 2>&1 || true

    echo -e "${GREEN}[OK]${NC} System optimizations applied (RPS mask=0x${rps_mask} on ${wan_if}, ${ncpus} CPUs)"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check root privileges
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root"
    exit 1
fi

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    log_error "Configuration file not found: $CONFIG_FILE"
    exit 1
fi

# Check if module file exists
if [ ! -f "$MODULE_PATH" ]; then
    log_error "Module file not found: $MODULE_PATH"
    log_info "Run 'make' first to build the module"
    exit 1
fi

# Parse configuration file
# Supports all v2.0 parameters including:
# - Basic: enabled, max_flows, flow_timeout
# - Queue: lan_wan_queue_*, wan_lan_queue_*
# - RTO: rto_min, rto_max
# - CC: init_cwnd, bandwidth_mbps
# - Features: tcp_spoofing, fake_ack, local_retrans, gso_enabled, gro_enabled
# - Learning: learning_enabled
# - ACK Pacing: ack_pacing, ack_delay_us, ack_bytes_threshold
# - Regional: region_learning, region_max, region_prefix
# - Debug: debug_level
# - Interface: wan_if, lan_if
parse_config() {
    local params=""
    while IFS= read -r line || [ -n "$line" ]; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue

        # Extract parameter=value pairs
        if [[ "$line" =~ ^[a-zA-Z_][a-zA-Z0-9_]*= ]]; then
            # Remove any inline comments
            local param_value="${line%%#*}"
            # Trim whitespace
            param_value="${param_value%"${param_value##*[![:space:]]}"}"

            if [ -n "$param_value" ]; then
                params="$params $param_value"
            fi
        fi
    done < "$CONFIG_FILE"
    echo "$params"
}

# Validate parameters
validate_params() {
    local params="$1"
    local warnings=0

    # Check for dangerous combinations
    if (echo "$params" | grep -q "fake_ack=1" || echo "$params" | grep -q "advinacc=1") &&
       ! echo "$params" | grep -q "local_retrans=1"; then
        log_warn "advinacc/fake_ack=1 without local_retrans=1 may cause data loss!"
        warnings=$((warnings + 1))
    fi

    # Check ACK pacing parameters
    if echo "$params" | grep -q "ack_pacing=1"; then
        log_info "ACK Pacing enabled - Fake ACKs will be sent at controlled intervals"
    fi

    # Check Regional Learning
    if echo "$params" | grep -q "region_learning=1"; then
        log_info "Regional Learning enabled - New flows will inherit optimal parameters"
    fi

    # Check FEC
    if echo "$params" | grep -q "fec_enabled=1"; then
        log_info "FEC enabled - Forward Error Correction active for packet recovery"
    fi

    return $warnings
}

# Unload module if loaded
unload_module() {
    if lsmod | grep -q "^${MODULE_NAME}"; then
        log_info "Unloading existing ${MODULE_NAME} module..."
        if rmmod "$MODULE_NAME" 2>/dev/null; then
            log_info "Module unloaded successfully"
            # Clear kernel log
            dmesg -c > /dev/null 2>&1 || true
        else
            log_error "Failed to unload module. Check if connections are active."
            return 1
        fi
    else
        log_info "Module ${MODULE_NAME} is not loaded"
    fi
}

# Load module with parameters
load_module() {
    local params="$1"

    log_info "Loading ${MODULE_NAME} with parameters:"
    echo ""

    # Group parameters by category for cleaner display
    echo "  === Basic ==="
    echo "$params" | tr ' ' '\n' | grep -E '^(enabled|max_flows|flow_timeout)=' | while read param; do
        echo "    $param"
    done

    echo "  === Queue ==="
    echo "$params" | tr ' ' '\n' | grep -E '^(lan_wan_queue|wan_lan_queue)' | while read param; do
        echo "    $param"
    done

    echo "  === BDP-Aware Queue ==="
    echo "$params" | tr ' ' '\n' | grep -E '^(queue_bdp|queue_max|wan_rtt_ms)' | while read param; do
        echo "    $param"
    done

    echo "  === RTO/CC ==="
    echo "$params" | tr ' ' '\n' | grep -E '^(rto_|wan_syn_fail_open_ms|init_cwnd|bandwidth_mbps)' | while read param; do
        echo "    $param"
    done

    echo "  === Shaper / Policy ==="
    echo "$params" | tr ' ' '\n' | grep -E '^(shaper_enabled|wan_kbps|wan_in_kbps|sm_burst|bypass_overflows|max_acc_flow_tx_kbps|subnet_acc|lan_segment)=' | while read param; do
        echo "    $param"
    done

    echo "  === Byte Cache ==="
    echo "$params" | tr ' ' '\n' | grep -E '^byte_cache_' | while read param; do
        echo "    $param"
    done

    echo "  === Features ==="
    echo "$params" | tr ' ' '\n' | grep -E '^(tcp_spoofing|advacc|advinacc|fake_ack|local_retrans|gso_|gro_|fastpath_|learning_enabled)' | while read param; do
        echo "    $param"
    done

    echo "  === ACK Pacing ==="
    echo "$params" | tr ' ' '\n' | grep -E '^ack_' | while read param; do
        echo "    $param"
    done

    echo "  === Regional Learning ==="
    echo "$params" | tr ' ' '\n' | grep -E '^region_' | while read param; do
        echo "    $param"
    done

    echo "  === Debug ==="
    echo "$params" | tr ' ' '\n' | grep -E '^debug_level' | while read param; do
        echo "    $param"
    done

    echo ""

    if insmod "$MODULE_PATH" $params; then
        log_info "Module loaded successfully"
        return 0
    else
        log_error "Failed to load module"
        return 1
    fi
}

# Show quick status after loading
show_quick_status() {
    echo ""
    echo -e "${CYAN}=== Quick Status ===${NC}"

    local mem=$(lsmod | grep "^${MODULE_NAME}" | awk '{print $2}')
    echo "  Module: ${MODULE_NAME}"
    echo "  Memory: ${mem} bytes"

    if [ -d "/proc/pep" ]; then
        echo "  Status: Running"
        if [ -f "/proc/pep/stats" ]; then
            echo ""
            echo "  Initial Stats:"
            head -5 /proc/pep/stats 2>/dev/null | while read line; do
                echo "    $line"
            done
        fi
    else
        echo "  Status: Not Running"
    fi
}

# Main
main() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   RFC 3135 PEP TCP Accelerator v2.0 - Module Loader      ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    log_info "Config file: $CONFIG_FILE"
    log_info "Module path: $MODULE_PATH"
    echo ""

    # Apply system optimizations
    configure_system
    echo ""

    # Parse config
    PARAMS=$(parse_config)

    if [ -z "$PARAMS" ]; then
        log_warn "No parameters found in config file, using defaults"
    fi

    # Validate parameters
    validate_params "$PARAMS"
    echo ""

    # Unload if loaded
    if ! unload_module; then
        exit 1
    fi

    # Small delay to ensure cleanup
    sleep 0.5

    # Load with new parameters
    if ! load_module "$PARAMS"; then
        exit 1
    fi

    # Show status
    show_quick_status

    echo ""
    log_info "Configuration applied successfully!"
    log_info "View full status with: ./pepctl.sh status"
    log_info "View learning stats:  ./pepctl.sh learning"
    log_info "View regional stats:  ./pepctl.sh regions"
}

main "$@"
