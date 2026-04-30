# DNS Cache Behavior Analysis via DART

This experiment evaluates DNS resolver cache behavior within DART via Tranco Top 1k domains. DNS-Monitor observes cache insertion dynamics, source distribution, preference patterns, and state transitions.

## How to Run

```bash
dnsb run cache.yml
```

## Key Files

- `cache.yml` — DNS-BUILDER configuration with monitor and cache analysis integration
- `analysis/` — Post-processing scripts for cache dump analysis
- `top-1k.txt` — Tranco Top 1K domain test dataset

## Outputs

The experiment generates cache analysis data including:
- Source distribution of cache insertions (which authoritative layer the record came from)
- Insertion rate dynamics over time
- Preference heatmap (which record types resolvers favor)
- Transition matrix showing cache state changes