# RuleSet Rules

RuleSet is a module for version rule matching, supporting version validation, base image selection, dependency management, and custom rule processing.

## Basic Concepts

| Class | Description |
|----|------|
| `Version` | Semantic version parsing and comparison, supports `>=`, `<` and other comparison operations |
| `Rule` | Version constraint rule, supports intervals and comparison operators |
| `RuleEntry` | A single rule entry, containing `range`, `set`, `val` fields |
| `RuleSet` | Collection of rule entries; evaluates a version and returns validation status, base image, dependency list, and custom results |
| `RuleHandler` | Custom rule handler function type, signature is `(entry: RuleEntry, result: dict) -> None` |

## RuleSet Format

RuleSet uses a **JSON array format**, where each rule is a dictionary:

```json
[
    { "range": "[9.18.0, 9.18.32]", "set": "valid" },
    { "range": ">= 9.20.0", "val": "22.04", "set": "base" },
    { "range": ">= 9.15.0", "val": "libuv1-dev", "set": "dep" },
    { "range": ">= 9.18.0", "val": "dnssec", "set": "feature" }
]
```

### Field Descriptions

| Field | Required | Description |
|------|:----:|------|
| `range` | Yes | Version range expression |
| `set` | Yes | Rule type: `valid`, `base`, `dep`, or custom type |
| `val` | Conditional | Rule value (required for `base` and `dep` types, not needed for `valid` type, optional for custom types) |

## Rule Types (set)

### Built-in Types

| Type | Description | `val` Example |
|------|------|------------|
| `valid` | Marks valid version ranges | No `val` needed |
| `base` | Sets the base image or OS version | `"22.04"`, `"python:3.12-slim"` |
| `dep` | Adds build dependency packages | `"libuv1-dev"`, `"libnghttp2-dev"` |

### Custom Types

Plugins can define their own rule types, processed via `RuleHandler`:

| Type | Description | Processing Method |
|------|------|----------|
| Custom | Software-specific rules | Register handlers via `Image.register_rule_handler()` |

**Example**: CoreDNS plugin rules

```json
[
    { "range": ">= 1.8.0", "val": "prometheus", "set": "plugin" },
    { "range": ">= 1.9.0", "val": "etcd", "set": "backend" }
]
```

### Rule Evaluation

When `RuleSet.evaluate(version, handlers)` is called:

- **valid**: Any matching `valid` rule sets the result to `True`
- **base**: The **first matching** `base` rule wins (subsequent matches are ignored)
- **dep**: **All matching** `dep` rules accumulate into the `deps` list
- **Custom**: Processed by registered `RuleHandler`, results stored in the `extras` dictionary

## Range Syntax

Version range expressions support multiple forms:

### Closed Interval

```json
{ "range": "[1.0.0, 2.0.0]", "set": "valid" }
```

Meaning: `1.0.0 <= version <= 2.0.0` (inclusive on both ends)

### Open Interval

```json
{ "range": "(1.0.0, 2.0.0)", "set": "valid" }
```

Meaning: `1.0.0 < version < 2.0.0` (exclusive on both ends)

### Half-open Interval

```json
{ "range": "[1.0.0, 2.0.0)", "set": "valid" }
{ "range": "(1.0.0, 2.0.0]", "set": "valid" }
```

Meaning:
- `[1.0.0, 2.0.0)` -> `1.0.0 <= version < 2.0.0`
- `(1.0.0, 2.0.0]` -> `1.0.0 < version <= 2.0.0`

### Comparison Operators

```json
{ "range": ">=1.5.0", "val": "22.04", "set": "base" }
{ "range": "<2.0.0", "val": "14.04", "set": "base" }
{ "range": "<=3.0.0", "set": "valid" }
```

Supported: `>=`, `>`, `<=`, `<`

### Exact Match

```json
{ "range": "9.13.4", "val": "python3-dnspython", "set": "dep" }
```

Meaning: Only matches `version == 9.13.4`

## Rule File Examples

### BIND Rules (`rules/bind`)

```json
[
    { "range": "[9.18.0, 9.18.32]", "set": "valid" },
    { "range": "[9.20.0, 9.20.16]", "set": "valid" },

    { "range": "<= 9.10.4", "val": "14.04", "set": "base" },
    { "range": "[9.10.5, 9.11.4]", "val": "16.04", "set": "base" },
    { "range": "[9.18.0, 9.20.0)", "val": "20.04", "set": "base" },
    { "range": ">= 9.20.0", "val": "22.04", "set": "base" },

    { "range": ">= 9.15.0", "val": "libuv1-dev", "set": "dep" },
    { "range": ">= 9.11.0", "val": "libnghttp2-dev", "set": "dep" },
    { "range": "< 9.18.0", "val": "python3-ply", "set": "dep" }
]
```

### Rules with Custom Types

```json
[
    { "range": "[1.8.0, 1.11.99]", "set": "valid" },
    { "range": ">= 1.9.0", "val": "22.04", "set": "base" },
    { "range": ">= 1.8.0", "val": "prometheus", "set": "plugin" },
    { "range": ">= 1.9.0", "val": "etcd", "set": "backend" }
]
```

## Rule File Locations

Rule files are stored in the `src/dnsbuilder/resources/images/rules/` directory, with filenames corresponding to software types:

| File | Software |
|------|------|
| `bind` | BIND DNS server |
| `unbound` | Unbound DNS resolver |
| `pdns_recursor` | PowerDNS Recursor |
| `knot_resolver` | Knot Resolver |
| `technitium` | Technitium DNS Server |
| `python` | Python base image |
| `judas` | Judas DNS tool |

## Python API

### Basic Usage

```python
from dnsbuilder.rules import Rule, Version, RuleSet, RuleEntry

# Create a RuleSet
ruleset = RuleSet([
    {"range": "[1.0.0, 2.0.0]", "set": "valid"},
    {"range": ">=1.5.0", "val": "22.04", "set": "base"},
    {"range": ">=1.8.0", "val": "libuv1-dev", "set": "dep"},
])

# Evaluate a version
result = ruleset.evaluate(Version("1.9.0"))
# Returns:
# {
#     "valid": True,
#     "base": "22.04",
#     "deps": ["libuv1-dev"],
#     "extras": {}
# }

# Version comparison
v1 = Version("9.18.0")
v2 = Version("9.20.0")
assert v1 < v2  # True

# Rule matching
rule = Rule("[9.18.0, 9.20.0]")
assert Version("9.19.0") in rule  # True
```

### Using Custom RuleHandler

```python
from dnsbuilder.rules import RuleSet, RuleEntry, RuleHandler, Version

# Define custom handlers
def handle_plugin(entry: RuleEntry, result: dict) -> None:
    """Process plugin rule type"""
    result["extras"].setdefault("plugins", []).append(entry.val)

def handle_backend(entry: RuleEntry, result: dict) -> None:
    """Process backend rule type (single value)"""
    result["extras"]["backend"] = entry.val

# Create a RuleSet with custom types
ruleset = RuleSet([
    {"range": ">= 1.8.0", "set": "valid"},
    {"range": ">= 1.9.0", "val": "22.04", "set": "base"},
    {"range": ">= 1.8.0", "val": "prometheus", "set": "plugin"},
    {"range": ">= 1.9.0", "val": "etcd", "set": "backend"},
])

# Pass handlers during evaluation
handlers = {
    "plugin": handle_plugin,
    "backend": handle_backend,
}
result = ruleset.evaluate(Version("1.9.0"), handlers=handlers)
# Returns:
# {
#     "valid": True,
#     "base": "22.04",
#     "deps": [],
#     "extras": {
#         "plugins": ["prometheus"],
#         "backend": "etcd"
#     }
# }
```

### RuleHandler Signature

```python
from typing import Dict, Any
from dnsbuilder.rules import RuleEntry

# RuleHandler type signature
def my_handler(entry: RuleEntry, result: Dict[str, Any]) -> None:
    """
    Custom rule handler.

    Args:
        entry: The matched rule entry, containing range, set, val fields
        result: The evaluation result dictionary, which can be modified (especially result["extras"])

    Typically operates on the result["extras"] dictionary to store custom results.
    """
    # Example: accumulate multiple values into a list
    result["extras"].setdefault("my_items", []).append(entry.val)

    # Example: set a single value (later matches will override)
    result["extras"]["my_value"] = entry.val
```

## Using Custom Rules in Image

See [Plugin Development Guide](../plugin.md#rule-handler-registration) for details. Key steps:

1. Register handlers in an Image subclass: `cls.register_rule_handler("plugin", handler)`
2. Override `_process_rule_extras()` to process evaluation results

```python
from dnsbuilder.abstractions import InternalImage
from dnsbuilder.rules import RuleEntry

class CoreDNSImage(InternalImage):
    @classmethod
    def _setup_handlers(cls):
        cls.register_rule_handler("plugin", cls._handle_plugin)
        cls.register_rule_handler("backend", cls._handle_backend)

    @staticmethod
    def _handle_plugin(entry: RuleEntry, result: dict):
        result["extras"].setdefault("plugins", []).append(entry.val)

    @staticmethod
    def _handle_backend(entry: RuleEntry, result: dict):
        result["extras"]["backend"] = entry.val

    def _process_rule_extras(self, extras: dict):
        if "plugins" in extras:
            self.plugins = extras["plugins"]
        if "backend" in extras:
            self.backend = extras["backend"]
```

## Further Reading

- [Internal Image Configuration](../config/images.md)
- [Configuration Processing Pipeline](../config/processing-pipeline.md)
- [Plugin Development Guide](../plugin.md) -- RuleHandler registration details