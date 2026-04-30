# Dynamic Constant Configuration

## Overview

The `.dnsbattribute` file allows you to dynamically override DNSBuilder's constant system at runtime without modifying source code. It is applicable for the following scenarios:

- Add custom log module aliases
- Support additional operating systems
- Define custom DNS software recognition patterns
- Add custom package managers
- Extend DNS software configuration block definitions

## File Location

Place the `.dnsbattribute` file in the **workdir** (the directory specified by the `--workdir` option, or the directory containing the configuration file). The file is automatically loaded when dnsbuilder configuration is initialized.

```
workdir/
├── config.yml
├── .dnsbattribute          ← Auto-loaded
├── top-1k.txt
└── shared/
```

## Configuration Format

The `.dnsbattribute` file uses YAML format, containing the constants to override:

```yaml
# Add custom log aliases
LOG_ALIAS_MAP:
  custom: "dnsbuilder.custom.module"
  mylog: "dnsbuilder.my.custom.logger"

# Extend supported operating systems
SUPPORTED_OS:
  - alpine
  - rocky

# Add custom DNS software recognition patterns
RECOGNIZED_PATTERNS:
  my_custom_dns:
    - r"\bmydns\b"
    - r"\bcustom-bind\b"
```

## Override Strategies

The loader supports three different override strategies:

### Replace

For non-dict, non-list types, the entire constant is replaced:

```yaml
DEFAULT_OS: "alpine"  # Replace entire value
```

### Merge

Dict types undergo **deep merge**, preserving original key-value pairs:

```yaml
LOG_ALIAS_MAP:
  new_alias: "dnsbuilder.new.module"
  # Original aliases are preserved
```

Result:
```python
LOG_ALIAS_MAP = {
    "sub": "dnsbuilder.builder.substitute",
    # ... original entries ...
    "new_alias": "dnsbuilder.new.module",
}
```

### Extend

List types are **extended**, with new elements appended to the end:

```yaml
SUPPORTED_OS:
  - alpine
  - rocky
```

Result:
```python
SUPPORTED_OS = ["ubuntu", "debian", "alpine", "rocky"]
```

## Examples

### Add Custom Log Aliases

```yaml
# .dnsbattribute
LOG_ALIAS_MAP:
  mymod: "dnsbuilder.my.module"
  dbg: "dnsbuilder.debug"
```

Then use in the environment:
```bash
export DNSB_DEBUG="mymod,dbg"
dnsbuilder build config.yml
```

### Support Alpine Linux

```yaml
# .dnsbattribute
SUPPORTED_OS:
  - alpine

BASE_PACKAGE_MANAGERS:
  apk:
    supported_os: ["alpine"]
    check_cmd: "command -v apk >/dev/null 2>&1"
    install_cmd: "apk add --no-cache {packages}"
    cleanup_cmd: ""
```

### Add Custom DNS Software

```yaml
# .dnsbattribute
RECOGNIZED_PATTERNS:
  my_dns:
    - r"\bmydns\b"
    - r"\bcustom-bind\b"
```

> **Note**: Configuration block definitions are now managed through the Section system. To define custom configuration blocks, register Section classes via plugins.

### Extend Custom Package Managers

```yaml
# .dnsbattribute
SOFT_PACKAGE_MANAGERS:
  custom_pkg:
    check_cmd: "command -v custom-pkg >/dev/null 2>&1"
    install_cmd: "custom-pkg install {packages}"
    cleanup_cmd: "custom-pkg cleanup"
    base_requirements:
      apt: ["custom-pkg"]
      apk: ["custom-pkg"]
```

## Overridable Constants

Commonly overridable constants:

| Constant | Type | Purpose |
|------|------|------|
| `LOG_ALIAS_MAP` | dict | Log module name aliases |
| `SUPPORTED_OS` | list | Supported operating system list |
| `DEFAULT_OS` | str | Default OS when not specified |
| `RECOGNIZED_PATTERNS` | dict | DNS software recognition patterns |
| `BEHAVIOR_TYPES` | set | Supported behavior types |
| `RESOURCE_PREFIX` | str | Resource URL prefix |
| `STD_BUILD_PREFIX` | str | Standard build reference prefix |
| `BASE_PACKAGE_MANAGERS` | dict | Base package manager configuration |
| `SOFT_PACKAGE_MANAGERS` | dict | Software package manager configuration |

See `src/dnsbuilder/constants.py` for the complete list.

## Logging

The attribute loader logs all operations at INFO level:

```
[AttributeLoader] Loaded attributes from /path/to/.dnsbattribute
[AttributeLoader] Attributes to override: ['LOG_ALIAS_MAP', 'SUPPORTED_OS']
[AttributeLoader] Updated constant 'LOG_ALIAS_MAP'
[AttributeLoader] Updated constant 'SUPPORTED_OS'
```

Enable debug logging to view detailed merge operations:

```bash
export DNSB_DEBUG="auto"
dnsbuilder build config.yml
```

## Related Documentation

- `constants.py` — Source definition of all constants
- [Plugin Development](plugin.md) — Plugin `attributes` property uses the same mechanism