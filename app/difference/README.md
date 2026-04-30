# DNS Resolve Behavior Difference Analysis via DART

This experiment detects behavioral differences between multiple DNS recursive resolver implementations by comparing their responses and the resolution path to the same set of queries. DNS-FUZZER sends standard and crafted queries, and DNS-Monitor observes whether different resolvers respond consistently or diverge — revealing RFC compliance discrepancies.

## Tested Resolvers

The experiment deploys multiple resolver instances simultaneously:

- BIND 9.18.0 / 9.21.15
- Unbound 1.17.1 / 1.24.2
- PowerDNS Recursor 4.5.4 / 5.2.6
- Knot Resolver 5.5.2 / 6.0.16

## How to Run

```bash
dnsb run differ.yaml
```

## Key Files

- `differ.yaml` — DNS-BUILDER configuration deploying multiple resolver instances with fuzzer and monitor integration
- `analysis/` — Comparison analysis scripts and results
- `top-1k.txt` — Tranco Top 1K domain test dataset
