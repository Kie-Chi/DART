# dnsb_utils

Utility plugin package for DNS Builder auto scripts.

## Install (local workspace)

```bash
pip install -e ./dnsb_utils
```

## What it provides

- `UtilsPlugin`
- Auto helper: `zone_from_file`

## Examples

```yaml

builds:
    sld:
        image: bind
        ref: std:auth
        behavior: |
            example.com master * A 6.6.6.6
        auto:
            setup: zone_from_file(workdir / "db.example.com")

```
