# DNS-SAK

**DNS Spoofing Attack Kit** — a C-based framework for researching and reproducing DNS cache poisoning vulnerabilities.

## Overview

DNS-SAK is a research tool that implements several well-known DNS cache poisoning attacks in a unified, high-performance C framework. It is designed for academic measurement studies of DNS resolver security, providing reproducible attack workflows and instrumentation for evaluating resolver robustness.

**This tool is intended solely for authorized security research and educational purposes.** Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical.

## Attack Implementations

DNS-SAK implements the following DNS cache poisoning attacks:

| Module | Attack | Description |
|--------|--------|-------------|
| `kaminsky_attack` | Kaminsky Attack | The classic DNS cache poisoning attack that floods a resolver with spoofed responses to win the TXID/port race. |
| `ipfragment_attack` | IP Fragmentation Attack | Exploits IP fragmentation to inject poisoned DNS data via second-fragment-only spoofing, bypassing some anti-poisoning defenses. |
| `ipfragment_attack_low` | IP Fragmentation Attack (Standalone) | A simplified standalone version of the IP fragment attack, operating in a sequential loop without the sender framework. |
| `saddns_attack` | SAD DNS Attack | Implements the Side-channel Attack on DNS (SAD DNS), which leverages ICMP rate-limiting side channels to leak source port and TXID information. |
| `rebirthday_attack` | RebirthDay Attack | Implements the RebirthDay attack that uses ECS (EDNS Client Subnet) queries as a side channel to leak resolver state, combined with multi-sender flooding. |

## Utility Programs

| Module | Description |
|--------|-------------|
| `udpscan` | Standalone UDP port scanner for discovering open resolver ports (used as a sub-component in SAD DNS). |
| `probe` | DNS probe tool that sends periodic A queries to a target resolver for latency/availability measurement. |
| `listener` | A simple DNS listener that responds to queries, useful as a test authoritative server. |

## Architecture

DNS-SAK is built on a modular sender framework that supports multiple packet generation and transmission strategies:

- **One-Shot**: Generates and sends a single batch of packets.
- **Burst**: Periodically generates and sends batches of packets at configurable intervals.
- **PPS (Packets Per Second)**: Rate-controlled sending with a target PPS, using a producer-consumer model with buffer management.
- **Multitask**: Accepts externally submitted work items (from other threads or callbacks), enabling flexible integration with scan-triggered attack flows.
- **Multi-Sender**: Parallel sending across multiple raw socket instances, optimized with `sendmmsg` for batch kernel-level transmission.

All strategies use a common `Arena`-based memory allocator for efficient, zero-overhead packet construction with automatic cleanup.

## Core Libraries

- `dns.c` — DNS packet construction, encoding, and parsing.
- `fake.c` — Spoofed DNS response generation (CNAME chains, NS delegation, A records).
- `network.c` — Raw IP/UDP packet crafting, fragmentation, and transmission.
- `scanner.c` — Binary-search-based UDP port scanning with ICMP side-channel detection.
- `parser.c` — Full DNS packet parser for response verification.
- `pcap_writer.c` — PCAP recording of sent packets for offline analysis.
- `sender.c` / `strategy.c` — The sender framework and strategy implementations.
- `arena.c` — Arena-based memory allocator (credit: Alexey Kutepov, MIT license).

## Build

```bash
mkdir -p build && cd build
cmake .. && make
```

Dependencies: `libuv`, `libpcap`, pthreads.

## Usage

Each attack module is a standalone executable with command-line options. Examples:

```bash
# Kaminsky attack
./kaminsky_attack -t <victim_ip> -p <victim_port> -s <auth_ip> -d <domain> -n <ns_name> -i <ns_ip>

# IP Fragment attack
./ipfragment_attack -f <forwarder_ip> -a <auth_ip> -p <prefix> -v <victim_domain> -d <ip> -n <name> -i <ip> -l <chain_length>

# SAD DNS attack
./saddns_attack <resolver_ip> <resolver_ip_in> <poison_domain> <poison_ip> <poison_ns> <ns_server_ip_list>

# RebirthDay attack
./rebirthday_attack -t <victim_ip> -a <auth_ip> -d <domain> -p <poison_ip> [-u 0|1|2|3] [-r <rounds>]
```

## Ethical Use Notice

This tool is developed for **authorized DNS security research** only. It must only be used in controlled laboratory environments with explicit permission from all involved parties. Misuse of this tool to attack real-world DNS infrastructure without authorization is a violation of law and professional ethics.

If you use DNS-SAK in your research, please cite appropriately and disclose your experimental setup transparently in your publications.

## License

This project is released for academic research purposes. Third-party components retain their original licenses (see `include/arena.h` for Arena allocator license).