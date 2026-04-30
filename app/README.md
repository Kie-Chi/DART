# Application-Layer Evaluation via DART

This directory contains DNS application-layer evaluation experiments that leverage DNS-FUZZER and DNS-Monitor to analyze resolver behavior across three dimensions.

## Subdirectories

### `cache/` — DNS Cache Behavior Analysis

Evaluates DNS resolver cache behavior using DART. The experiment analyze serveral DNS software cache behaviors via Tranco Top 1k domains, and uses DNS-Monitor to observe:

- **Source distribution** of cache insertions (which zone layer the cached record originates from)
- **Insertion rate dynamics** over time
- **Preference patterns** (heatmaps showing which record types are favored)
- **Transition matrices** showing cache state changes

Key files:
- `cache.yml` — DNS-BUILDER configuration spawning the full topology with monitor integration
- `analysis/` — Post-processing scripts for cache dump analysis
- `top-1k.txt` — Tranco Top 1K domain list used as the test dataset

### `difference/` — DNS Resolve Behavior Difference Analysis

Detects behavioral differences between multiple DNS recursive resolver implementations (BIND, Unbound, PowerDNS, Knot Resolver) by comparing their responses and the resolution path to the same set of queries. DNS-FUZZER sends standard and crafted queries, and DNS-Monitor observes whether different resolvers respond consistently or diverge.

Key files:
- `differ.yaml` — DNS-BUILDER configuration deploying multiple resolver instances simultaneously
- `analysis/` — Comparison analysis scripts

### `error/` — RFC Handling Testing

Tests how DNS resolvers handle malformed, non-standard, or protocol-violating packets. Uses DNS-FUZZER's custom packet generators to craft packets that violate specific RFC requirements (e.g., TC-flagged truncated packets per RFC1123, malformed EDNS0 options), then analyzes whether resolvers correctly reject or mishandle these inputs.

Key files:
- `error.yml` — DNS-BUILDER configuration with fuzzer and monitor integration
- `custom_packets.py` — Custom DNS packet generators for RFC compliance testing
- `test_custom.yml` — Query targets for custom packet tests

## How to Run

Each experiment is configured as a DNS-BUILDER project. Build and run with:

```bash
dnsb run <config.yml>
```