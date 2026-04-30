# DNS RFC Handling Testing via DART

This experiment tests how DNS resolvers handle malformed, non-standard, or protocol-violating packets. DNS-FUZZER's custom packet generators craft packets that violate specific RFC requirements (e.g., TC-flagged truncated packets per RFC1123, malformed EDNS0 options). DNS-Monitor analyzes whether resolvers correctly reject or mishandle these inputs.

## How to Run

```bash
dnsb run error.yml
```

For custom packet testing:

```bash
dnsb run test_custom.yml
```

## Key Files

- `error.yml` — DNS-BUILDER configuration with fuzzer and monitor integration for RFC compliance testing
- `custom_packets.py` — Custom DNS packet generators for various RFC compliance scenarios
- `test_custom.yml` — Configuration for custom packet test targets
- `analysis/` — Analysis results and comparison data