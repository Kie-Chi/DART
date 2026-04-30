# DNS Builder Configuration Generation and Mounting Mechanism

This document details how DNS Builder generates configuration files for different DNS software and performs mounting, including the Section system, configuration fragment management, and the Includer mechanism.

---

## Overview

DNSBuilder identifies DNS software configurations by the `.conf` suffix of mounted files and assists with mounting. For example, `should_be_included.conf` will be automatically referenced into the DNS software's main configuration.

For details, see the subsequent `Section/SectionReference` introduction.
```shell
named.conf
>>> is_conf: true, section: global, params: {}

named.a.b.c.d.conf
>>> is_conf: true, section: global, params: {}

named.conf.options
>>> is_conf: true, section: options, params: {}

named.conf.zone?name=www.example.com
>>> is_conf: true, section: zone, params: {name : "www.example.com"}

```


## Concepts

### 1.1 Section and SectionInfo

The `Section` system defines the configuration block structures supported by each DNS software. Each software (BIND, Unbound, etc.) has a corresponding `Section` subclass that defines the configuration blocks it supports.

**Section class attributes**:

```python
class Section(ABC):
    # Software-specific configuration
    conf_suffix: ClassVar[str] = ".conf"    # Configuration file suffix
    include_tpl: ClassVar[str] = ""          # include statement template
```

| Attribute | Description |
|------|------|
| `conf_suffix` | Configuration file suffix, used for generating file names |
| `include_tpl` | include statement template, e.g. `'include "{path}";'` |

**SectionInfo** describes the metadata of a single configuration block:

```python
@dataclass
class SectionInfo:
    name: str              # Block name, e.g. "options", "zone", "server"
    template: str          # Format template, e.g. "options {{\n{content}\n}};"
    indent: int = 4        # Content indentation spaces
    params: Set[str] = {}  # Required parameters, e.g. {"name"} for zone "example.com"
    repeatable: bool = False  # Whether the block can appear repeatedly
    wrap_re: str = None    # Regular expression for locating the block (auto-generated)
```

**Key attribute descriptions**:

| Attribute | Description |
|------|------|
| `template` | Defines the format template for the block, must contain the `{content}` placeholder |
| `params` | Template parameter set, e.g. the `zone` block requires a `name` parameter |
| `repeatable` | `False` means the block can only appear once (e.g. `options`), `True` means it can appear multiple times (e.g. `zone`) |

### 1.2 SectionReference (Configuration Reference)

`SectionReference` parses the target section and parameters from a configuration file path.

**Supported path formats**:

```
/path/to/file.conf[?param=value&param2=value2][#section]
```

**Parsing rules**:

| Format | Example | Parsing Result |
|------|------|---------|
| Suffix format | `named.conf.options` | section = `options` |
| Fragment format | `named.conf#options` | section = `options` |
| With parameters | `zones.conf?name=example.com#zone` | section = `zone`, params = `{"name": "example.com"}` |

**Priority**: `#fragment` > `.suffix` > `"global"`

### 1.3 ConfigFragment (Configuration Fragment)

`ConfigFragment` represents a configuration fragment to be assembled:

```python
class ConfigFragment(BaseModel):
    src: DNSBPath              # Source file path
    dst: str                   # Destination path inside container
    dcr: Optional[str]         # Docker-compose relative path
    section: str = "global"    # Target section
    is_main: bool = False      # Whether it is the global main config
    content: Optional[str]     # Optional content
    params: Dict[str, Any]     # Section template parameters
```

**Workflow**:

1. Only fragments with `section == "global"` and `is_main == True` become the **global main config**
2. All other fragments are added to `_pending_fragments` awaiting assembly

---

## 2. Section System Details

### 2.1 Sections Supported by Each Software

**BIND**:

| Section | repeatable | params | Template Example |
|---------|------------|--------|---------|
| global | False | - | `{content}` |
| options | False | - | `options {\n{content}\n};` |
| logging | False | - | `logging {\n{content}\n};` |
| zone | True | `name` | `zone "{name}" {\n{content}\n};` |
| acl | True | `name` | `acl "{name}" {\n{content}\n};` |
| key | True | `key_name` | `key "{key_name}" {\n{content}\n};` |
| view | True | `name` | `view "{name}" {\n{content}\n};` |
| controls | False | - | `controls {\n{content}\n};` |
| server | False | - | `server {\n{content}\n};` |

**Unbound**:

| Section | repeatable | Template Example |
|---------|------------|---------|
| global | False | `{content}` |
| server | True | `server:\n{content}` |
| remote-control | False | `remote-control:\n{content}` |
| forward-zone | True | `forward-zone:\n{content}` |
| stub-zone | True | `stub-zone:\n{content}` |
| auth-zone | True | `auth-zone:\n{content}` |

**PowerDNS Recursor / Knot Resolver**:

Only supports the `global` section.

### 2.2 Section Template Parameters

Some sections require additional parameters to format the block header:

**BIND zone example**:

```yaml
volumes:
  - ./zones/example.conf?name=example.com#zone:/etc/named/zones/example.conf
```

Parsed as:
- `section = "zone"`
- `params = {"name": "example.com"}`

Generated configuration:
```bind
zone "example.com" {
    # File content...
};
```

**BIND acl example**:

```yaml
volumes:
  - ./acls/trusted.conf?name=trusted#acl:/etc/named/acls/trusted.conf
```

Generated:
```bind
acl "trusted" {
    192.168.1.0/24;
    10.0.0.0/8;
};
```

---

## 3. Includer Mechanism

### 3.1 How It Works

The `Includer` is responsible for assembling all configuration fragments into the global main config.

**Core process**:

```
┌─────────────────────────────────────────────────────────────────┐
│                      Includer.assemble()                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │ Check self.main │
                    │ (global main)   │
                    └─────────────────┘
                              │
        ┌─────────────────────┴─────────────────────┐
        ▼                                           ▼
┌───────────────┐                         ┌─────────────────┐
│ section ==    │                         │ section !=      │
│ "global"      │                         │ "global"        │
└───────────────┘                         └─────────────────┘
        │                                           │
        ▼                                 ┌─────────┴─────────┐
┌───────────────┐                         ▼                   ▼
│ Directly      │                 ┌───────────────┐   ┌───────────────┐
│ include into  │                 │ repeatable    │   │ Non-repeatable│
│ main config   │                 │ = True        │   │ = False       │
└───────────────┘                 └───────────────┘   └───────────────┘
                                          │                   │
                                          ▼                   ▼
                                  ┌───────────────┐   ┌───────────────┐
                                  │ Create new    │   │ Try to inject │
                                  │ block and     │   │ into existing │
                                  │ append        │   │ block or      │
                                  └───────────────┘   │ create new    │
                                                      └───────────────┘
```

### 3.2 Fragment Processing Strategy

| Condition | Processing Method |
|------|---------|
| `section == "global"` | Append include directly at the end of the main config |
| `repeatable == True` | Create a new block and append it to the main config |
| `repeatable == False` and block already exists | Inject include into the existing block |
| `repeatable == False` and block does not exist | Create a new block and append it to the main config |

### 3.3 Includer Implementations for Each Software

All Includers inherit from `BaseIncluder` and only need to implement the `inject()` method. The `include_tpl` is obtained from the corresponding Section class.

#### BindIncluder

```python
class BindIncluder(BaseIncluder):
    """BIND-style configuration assembler, uses bracket counting for injection"""

    def inject(self, content: str, section: str, lines: List[str]) -> Tuple[str, bool]:
        """Find the block end position via bracket counting and inject content"""
        # ... bracket counting logic ...
        return updated_content, True  # or (content, False) on failure
```

**Characteristics**:
- `include_tpl` comes from `BindSection`: `'include "{path}";'`
- Supports `block_pattern` for detecting existing blocks
- For non-repeatable blocks like `options`, `logging`, injects into existing blocks via bracket counting
- For repeatable blocks like `zone`, `acl`, creates a new block each time

**Generation example**:

```bind
# options block injection
options {
    listen-on port 53 { any; };
    # Auto Generated by DNS-Builder
    include "/etc/named/options/custom.conf";
};

# zone block creation
zone "example.com" {
    # Auto Generated by DNS-Builder
    include "/etc/named/zones/example.conf";
};
```

#### UnboundIncluder

```python
class UnboundIncluder(BaseIncluder):
    """Unbound configuration assembler, does not support injection"""

    def inject(self, content: str, section: str, lines: List[str]) -> Tuple[str, bool]:
        """Unbound has no clear block end markers, injection is not supported"""
        return content, False
```

**Characteristics**:
- `include_tpl` comes from `UnboundSection`: `'include: "{path}"'`
- All sections are treated as repeatable (injection is not supported)
- Uses Section templates to wrap includes

**Generation example**:

```yaml
# Auto Generated by DNS-Builder
server:
    # Auto Generated by DNS-Builder
    include: "/etc/unbound/server.conf"

# Auto Generated by DNS-Builder
forward-zone:
    # Auto Generated by DNS-Builder
    include: "/etc/unbound/forward.conf"
```

#### PdnsRecursorIncluder

```python
class PdnsRecursorIncluder(Includer):
    """PowerDNS Recursor uses include-dir directive"""
    _tmpl = '\n# include {config_line}'
    _write = "\n# Auto Generated by DNS Builder\ninclude-dir={include_dir}\n"
```

**Characteristics**:
- Does not inherit `BaseIncluder` (uses a special include-dir mechanism)
- Moves configuration files to a unified include directory
- Uses the `include-dir` directive

**Generation example**:

```ini
# Auto Generated by DNS Builder
include-dir=/usr/local/etc/includes
# include original/path.conf -> /usr/local/etc/includes/file.conf
```

#### KnotResolverIncluder

```python
class KnotResolverIncluder(Includer):
    """Knot Resolver uses Lua dofile() function"""
    _tmpl = "\n-- Auto Generated by DNS Builder\ndofile('{config_line}')\n"
```

**Characteristics**:
- Does not inherit `BaseIncluder` (uses Lua format)
- `include_tpl` comes from `KnotResolverSection`: `"dofile('{path}')"`
- Only supports the global section

---

## 4. Configuration File Path Syntax

### 4.1 Basic Format

Configuration file mount paths can use special syntax to specify sections and parameters:

```yaml
volumes:
  # Basic format: container path
  - ./local.conf:/etc/named.conf

  # Suffix format: specify section
  - ./options.conf:/etc/named.conf.options      # section = "options"
  - ./logging.conf:/etc/named.conf.logging      # section = "logging"

  # Fragment format: explicitly specify section
  - ./custom.conf:/etc/named.conf#server        # section = "server"

  # With parameters format
  - ./example.conf:/etc/zones.conf?name=example.com#zone
```

### 4.2 Path Parsing Examples

| Container Path | Parsing Result |
|---------|---------|
| `/etc/named.conf` | section = `global`, becomes the main config |
| `/etc/named.conf.options` | section = `options` |
| `/etc/named.conf.logging` | section = `logging` |
| `/etc/zones.conf#zone` | section = `zone` |
| `/etc/zones.conf?name=com#zone` | section = `zone`, params = `{"name": "com"}` |
| `/etc/acl.conf?name=trusted#acl` | section = `acl`, params = `{"name": "trusted"}` |

### 4.3 File Naming Conventions

It is recommended to use the `.conf.<section>` suffix for naming:

```
configs/
├── named.conf              # global section (main configuration)
├── named.conf.options      # options section
├── named.conf.logging      # logging section
├── named.conf.controls     # controls section
└── zones/
    ├── example.conf?name=example.com#zone
    └── test.conf?name=test.com#zone
```

---

## 5. Behavior Configuration Generation

### 5.1 BehaviorArtifact

`BehaviorArtifact` is the output structure generated by behaviors:

```python
class BehaviorArtifact(BaseModel):
    config_line: str                    # Configuration line content
    section: str = "global"             # Target section
    section_params: Dict[str, Any]      # Section template parameters
    new_volume: Optional[VolumeArtifact] # File to be generated (e.g. zone file)
    new_records: Optional[List[RR]]     # DNS records (Master behavior)
```

### 5.2 Configuration Generation Reference Table

| Behavior | BIND | Unbound |
|----------|------|---------|
| forward | `zone "x" { type forward; forwarders {...}; };` | `forward-zone:\n\tname: "x"\n\tforward-addr: ...` |
| stub | `zone "x" { type stub; masters {...}; };` | `stub-zone:\n\tname: "x"\n\tstub-addr: ...` |
| master | `zone "x" { type master; file "..."; };` | `auth-zone:\n\tname: "x"\n\tzonefile: "..."` |
| hint | Generate root.hints + zone configuration | `root-hints: "..."` (server section) |

---

## 6. Complete Usage Examples

### 6.1 BIND Recursive Resolver

```yaml
images:
  bind:
    ref: bind:9.18.0

builds:
  recursor:
    image: bind
    ref: std:recursor
    behavior: . hint root
    volumes:
      # Main configuration (global section)
      - ./configs/named.conf:/usr/local/etc/named.conf
      # options block configuration
      - ./configs/named.conf.options:/usr/local/etc/named.conf.options
      # Custom zone configuration
      - ./configs/custom.zone?name=custom.local#zone:/usr/local/etc/zones/custom.conf
```

**Generated result**:

`/usr/local/etc/named.conf`:
```bind
# Original content...
include "/usr/local/var/bind/rndc.key";

controls {
    inet * port 953 allow { internal-network; } keys { "rndc-key"; };
};

# Auto Generated by DNS-Builder
include "/usr/local/etc/named.conf.options";

# Auto Generated by DNS-Builder
zone "custom.local" {
    # Auto Generated by DNS-Builder
    include "/usr/local/etc/zones/custom.conf";
};

# Auto Generated by DNS-Builder
include "/usr/local/etc/zones/generated_zones.conf";
```

### 6.2 BIND Authoritative Server

```yaml
builds:
  auth:
    image: bind
    ref: std:auth
    behavior: |
      . master com NS tld
      com master example NS sld
    volumes:
      - ./configs/auth.conf:/usr/local/etc/named.conf
      - ./configs/acl.conf?name=trusted#acl:/usr/local/etc/acl.conf
```

**Generated result**:

`/usr/local/etc/named.conf`:
```bind
# Original content...

# Auto Generated by DNS-Builder
acl "trusted" {
    # Auto Generated by DNS-Builder
    include "/usr/local/etc/acl.conf";
};

# Auto Generated by DNS-Builder
include "/usr/local/etc/zones/generated_zones.conf";
```

`generated_zones.conf`:
```bind
zone "." {
    type master;
    file "/usr/local/etc/zones/db.root";
};

zone "com" {
    type master;
    file "/usr/local/etc/zones/db.com";
};
```

### 6.3 Unbound Forwarder

```yaml
images:
  unbound:
    ref: unbound:1.19.0

builds:
  forwarder:
    image: unbound
    ref: std:forwarder
    behavior: example.com forward 8.8.8.8,8.8.4.4
    volumes:
      - ./configs/server.conf:/usr/local/etc/unbound/server.conf
      - ./configs/remote.conf#remote-control:/usr/local/etc/unbound/remote.conf
```

**Generated result**:

`/usr/local/etc/unbound/unbound.conf`:
```yaml
# Original content...

# Auto Generated by DNS-Builder
server:
    # Auto Generated by DNS-Builder
    include: "/usr/local/etc/unbound/server.conf"

# Auto Generated by DNS-Builder
remote-control:
    # Auto Generated by DNS-Builder
    include: "/usr/local/etc/unbound/remote.conf"

# Auto Generated by DNS-Builder
include: "/usr/local/etc/zones/generated_zones.conf"
```

---

## 7. Key File Paths

| File | Path | Description |
|------|------|------|
| SectionInfo | `src/dnsbuilder/sections.py` | Section metadata definitions |
| Section implementations | `src/dnsbuilder/bases/sections.py` | Section definitions for each software |
| SectionReference | `src/dnsbuilder/io/path.py` | Path parsing |
| ConfigFragment | `src/dnsbuilder/datacls/artifacts.py` | Configuration fragment data structure |
| Includer base class | `src/dnsbuilder/abstractions.py` | Includer abstract class |
| Includer implementations | `src/dnsbuilder/bases/includers.py` | Includers for each software |

---

## 8. Extension Development

### 8.1 Adding a New Section

```python
from dnsbuilder.sections import Section, SectionInfo
from dnsbuilder import constants

class MyDNSSection(Section):
    # Software-specific configuration
    conf_suffix: str = ".conf"
    include_tpl: str = 'include "{path}";'

    @classmethod
    def get_sections(cls) -> Dict[str, SectionInfo]:
        return {
            "global": SectionInfo(name="global", template="{content}"),
            "server": SectionInfo(
                name="server",
                template="server {\n{content}\n}",
                indent=4,
                repeatable=False,
            ),
            "zone": SectionInfo(
                name="zone",
                template='zone "{name}" {{\n{content}\n}};',
                indent=4,
                params={"name"},
                repeatable=True,
            ),
        }
```

### 8.2 Adding a New Includer

It is recommended to inherit `BaseIncluder` and only implement the `inject()` method:

```python
from typing import List, Tuple
from dnsbuilder.abstractions import BaseIncluder

class MyDNSIncluder(BaseIncluder):
    """MyDNS configuration assembler

    include_tpl is obtained from MyDNSSection.include_tpl
    """

    def inject(self, content: str, section: str, lines: List[str]) -> Tuple[str, bool]:
        """
        Inject content into an existing block.

        If the software supports block injection, return (modified content, True).
        If not supported, return (original content, False), and BaseIncluder will automatically create a new block.
        """
        # When injection is not supported
        return content, False
```