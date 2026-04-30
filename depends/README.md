# Dependency Tools

This directory contains the core tools that DART depends on for environment orchestration, protocol fuzzing, DNS traffic monitoring, and DNS cache poisoning attack research. Each tool is a standalone package that can be installed independently.

## Tools

### `DNS-BUILDER/` — DNS Test Environment Orchestrator

DNS-BUILDER is the core framework that powers DART. It reads declarative YAML configuration files and automatically generates Docker Compose projects that spawn complete DNS test topologies — including recursive resolvers, authoritative servers, clients, and custom network configurations.

**Installation:**
```bash
pip install DNS-BUILDER

# If you want to build dnssec environments, also install bind-utils
# e.g. apt install bind-utils
```

**Usage:**
```bash
dnsb build config.yml    # Generate Docker Compose project
dnsb run config.yml      # Build and start the environment
```

**Requirements:** Python >= 3.12, Docker

See [DNS-BUILDER/README.md](DNS-BUILDER/README.md) for detailed documentation.

### `DNS-FUZZER/` — DNS Protocol Fuzzer & Analyzer

DNS-FUZZER is a DNS fuzzing tool that sends crafted or randomly mutated DNS queries to target resolvers and analyzes their responses. It supports:

- Standard query fuzzing against multiple resolver implementations
- Custom packet generation for RFC compliance testing
- Automated anomaly detection comparing resolver responses against expected behavior
- Concurrent fuzzing across multiple resolver instances

DNS-FUZZER is integrated into DART's application-layer evaluation experiments (`app/error/`, `app/difference/`) via volume mounts in DNS-BUILDER configurations.

### `DNS-Monitor/` — Real-Time DNS Traffic Monitor

DNS-Monitor provides real-time observability for DNS resolution behavior within DART environments. It operates as a passive monitoring service that:

- Captures DNS resolution traffic in real-time
- Analyzes resolver cache state transitions
- Detects anomalous DNS behavior patterns
- Supports per-resolver monitoring with minimal instrumentation overhead

DNS-Monitor is integrated into DART experiments via `network_mode: host` deployment and automated configuration generation, ensuring it can observe all DNS traffic within the closed test topology.

**Usage within DART:**
DNS-Monitor is typically launched automatically by DNS-BUILDER configs that include a `monitor` service definition. No separate installation is needed — it is installed and started within the Docker container.

### `DNS-SAK/` — DNS Spoofing Attack Kit

DNS-SAK is a C-based framework for researching and reproducing DNS cache poisoning vulnerabilities. It implements several well-known DNS cache poisoning attacks in a unified, high-performance framework, providing reproducible attack workflows and instrumentation for evaluating resolver robustness. Supported attacks include:

- **Kaminsky Attack** — Classic TXID/port race flooding attack
- **IP Fragmentation Attack** — Second-fragment spoofing to bypass anti-poisoning defenses
- **SAD DNS Attack** — ICMP rate-limiting side-channel attack to leak source port and TXID
- **RebirthDay Attack** — ECS side-channel attack combined with multi-sender flooding

DNS-SAK is built on a modular sender framework supporting one-shot, burst, PPS-rate-controlled, multitask, and multi-sender transmission strategies, with an arena-based memory allocator for efficient packet construction.

**This tool is intended solely for authorized security research and educational purposes.**

**Build:**
```bash
mkdir -p build && cd build
cmake .. && make
```

**Dependencies:** `libuv`, `libpcap`, pthreads

See [DNS-SAK/README.md](DNS-SAK/README.md) for detailed documentation.
