# RFC 3135 PEP — TCP Acceleration Kernel Module (Beta)

A Linux kernel module implementing [RFC 3135](https://www.rfc-editor.org/rfc/rfc3135.txt) Performance Enhancing Proxy (PEP) for transparent TCP acceleration. Designed for high-RTT, high-loss links such as satellite, cellular, cross-region WAN, and SD-WAN scenarios.

## What It Does

The module sits transparently on a gateway/middlebox and accelerates TCP connections without modifying clients or servers:

```
Client ←→ PEP (Split-TCP Proxy) ←→ Server
```

- Intercepts TCP via Netfilter hooks (PRE_ROUTING / POST_ROUTING)
- Splits each connection into two independent TCP segments
- Immediately ACKs the server (Advance ACK) so the server never sees client-side loss
- Immediately ACKs the client (Fake ACK) to decouple WAN latency from client behavior
- Handles retransmission locally from cache when client packets are lost

## Features

**Core PEP (RFC 3135)**
- Split-TCP with transparent SYN interception and TCP spoofing
- Sequence number translation (LAN ↔ WAN) with SACK block sync
- Fake ACK / Advance ACK with configurable pacing
- Local retransmission cache (32MB / 4096 packets, forced eviction)
- Complete TCP state machine (11 LAN states + 6 WAN states)
- FIN/RST passthrough for clean connection teardown
- Fail-open on WAN SYN timeout (avoids black-holing)

**Congestion Control**
- Configurable CWND, ssthresh, RTO parameters
- RACK-based loss detection + TLP tail loss probes
- ECN support with CE-triggered window reduction
- DSACK undo for spurious retransmission recovery
- Q-Learning adaptive congestion control (243 states × 5 actions)

**Traffic Management**
- Token bucket shaper (independent LAN→WAN / WAN→LAN)
- ACK pacing engine (100μs – 10ms intervals)
- Priority scheduler (HIGH / NORMAL / BULK)
- BDP-aware dynamic queue sizing

**Advanced**
- FEC forward error correction (XOR, adaptive K/N)
- Regional learning (per /24 prefix, new flows inherit history)
- PMTU discovery with ICMP handling
- Split-DL single-interface downlink acceleration (netif_rx fast path)
- GSO/GRO/RSC software offload (experimental)
- RTT active probing
- IP fragment reassembly + downlink reordering

## Requirements

- Linux kernel 5.10+ (tested on 6.1 ARM64)
- Kernel headers installed (`linux-headers-$(uname -r)`)
- GCC, make

## Quick Start

```bash
# Build
make -j$(nproc)

# Load with default config
sudo ./loadconfig.sh

# Check status
sudo ./pepctl.sh status

# View active flows
sudo ./pepctl.sh flows

# Unload
sudo rmmod pep_accelerator
```

## Configuration

Edit `pep.conf` then reload:

```bash
sudo ./loadconfig.sh
```

Key parameters:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `tcp_spoofing` | 1 | Enable Split-TCP spoofing |
| `advacc` | 1 | Server-side Advance ACK (download acceleration) |
| `fake_ack` | 1 | Client-side Fake ACK (upload acceleration) |
| `local_retrans` | 1 | Local retransmission cache |
| `split_dl_enabled` | 1 | Single-interface downlink acceleration |
| `init_cwnd` | 32 | Initial congestion window (segments) |
| `wan_rtt_ms` | 250 | Fallback WAN RTT for BDP calculation |
| `rto_min` | 500 | Minimum RTO (ms) |
| `bandwidth_mbps` | 200 | Estimated link bandwidth |
| `shaper_enabled` | 1 | Traffic shaper |
| `wan_kbps` | 40000 | WAN uplink bandwidth (kbps) |
| `wan_in_kbps` | 200000 | WAN downlink bandwidth (kbps) |
| `learning_enabled` | 1 | Q-Learning congestion control |
| `fec_enabled` | 1 | Forward error correction |
| `wan_if` / `lan_if` | — | Network interface names |
| `lan_segment` | — | LAN subnet to accelerate (e.g. `10.0.0.0/24`) |

See `pep.conf` for the full 60+ parameter list with descriptions.

## Management

```bash
# Real-time monitoring
sudo ./pepctl.sh watch

# Show Q-Learning statistics
sudo ./pepctl.sh learning

# Set debug level (0=off, 1=error, 2=warn, 3=info, 4=debug)
sudo ./pepctl.sh debug 3

# View kernel logs
sudo ./pepctl.sh log
```

## Architecture

```
                    Netfilter Hooks
                    ┌─────────────┐
  Client ──────────►│ PRE_ROUTING │──► Flow Lookup ──► Seq Translation
                    │             │    ──► Advance ACK ──► split_dl clone
                    └─────────────┘                        ──► netif_rx
                    ┌──────────────┐
  Client ◄──────────│ POST_ROUTING │◄── Fake ACK ◄── Queue ◄── WAN TX
                    │              │    ──► SYN intercept ──► WAN SYN
                    └──────────────┘
```

Source layout:

| Directory | Contents |
|-----------|----------|
| `src/` | 19 C source files (core, netfilter, spoofing, congestion, etc.) |
| `include/` | `pep_core.h`, `pep_learning.h` |
| `pep.conf` | Runtime configuration |
| `loadconfig.sh` | Module loader (parses pep.conf → insmod) |
| `pepctl.sh` | Management CLI |

## Performance

Tested on Debian 12 ARM64, single-interface mode (enp0s5):

| Scenario | Baseline | With PEP | Speedup |
|----------|----------|----------|---------|
| 10MB download (200ms RTT, 0.5% loss) | 255 KB/s | 3,784 KB/s | 14.8× |
| 1MB download (200ms RTT, 0.5% loss) | 276 KB/s | 1,560 KB/s | 5.6× |
| Speedtest download (no netem) | ~140 Mbps | ~100 Mbps | Near line-rate |
| Stability (3× speedtest) | — | 91–113 Mbps | Zero drops |

## References

- [RFC 3135 — Performance Enhancing Proxies](https://www.rfc-editor.org/rfc/rfc3135.txt)
- [CNES/pepsal — Userspace PEP reference](https://github.com/CNES/pepsal)

## License

AGPL-3.0-only. See source file headers.
