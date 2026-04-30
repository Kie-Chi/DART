# Plugin Development Guide

DNSBuilder supports a plugin system, allowing you to extend its functionality through custom DNS server implementations, behaviors, zone formats, and resources.

## Overview

Plugins can register the following components to extend DNSBuilder:

| Component | Description |
|------|------|
| **Image** | Docker image builder for DNS software |
| **Behavior** | DNS server behavior patterns (master, forward, stub, etc.) |
| **Includer** | Configuration file include pattern handler |
| **Section** | Configuration block definitions (options, zone, server, etc.) |
| **ZoneGenerator** | Custom zone file format generation (non-BIND format zonefile) |
| **Resources** | Templates, rules, defaults, control files, scripts |
| **Attributes** | Extension constants (via `attributes` class attribute) |

## Plugin Structure

A typical plugin package structure:

```
dnsb_mydns/
├── pyproject.toml
├── src/
│   └── dnsb_mydns/
│       ├── __init__.py          # Plugin entry point
│       ├── image.py             # Image implementation
│       ├── behavior.py          # Behavior implementation
│       ├── includer.py          # Includer implementation
│       ├── section.py           # Section implementation
│       ├── zone.py              # ZoneGenerator (optional)
│       └── resources/
│           ├── images/
│           │   ├── templates/
│           │   │   └── mydns    # Dockerfile template
│           │   ├── rules/
│           │   │   └── mydns    # Version rules
│           │   └── defaults/
│           │       └── mydns    # Default dependencies/tools
│           └── configs/
│               ├── mydns_master_base.conf
│               └── mydns_recursor_base.conf
```

## Creating a Plugin

### 1. Plugin Class

Create a class that inherits from `Plugin`:

```python
# src/dnsb_mydns/__init__.py
import logging
from typing import Dict, Any

from dnsbuilder.plugins import Plugin, PluginRegistry

from .zone import MyDNSZoneGenerator
from .behavior import MyDNSMasterBehavior
from .includer import MyDNSIncluder
from .section import MyDNSSection
from .image import MyDNSImage

logger = logging.getLogger(__name__)

__version__ = "0.0.1"

class MyDNSPlugin(Plugin):
    """MyDNS plugin"""

    # Required metadata
    name = "mydns"
    version = __version__
    description = "MyDNS server support"
    author = "Your Name"
    priority = 50  # Lower values are loaded earlier

    # Extension constants (same merge logic as .dnsbattribute)
    attributes: Dict[str, Any] = {
        "RECOGNIZED_PATTERNS": {
            "mydns": [r"\bmydns\b", r"\bmy-dns\b"]
        }
    }

    def on_load(self, registry: PluginRegistry):
        """Register MyDNS implementations"""
        logger.info("[MyDNSPlugin] Loading MyDNS plugin...")

        # Register Image
        registry.register_image("mydns", MyDNSImage)

        # Register Behavior
        registry.register_behavior("mydns", "master", MyDNSMasterBehavior)

        # Register Includer
        registry.register_includer("mydns", MyDNSIncluder)

        # Register Section (configuration block definition)
        registry.register_section("mydns", MyDNSSection)

        # Register Zone Generator (optional, for custom formats)
        registry.register_zone_generator("mydns", MyDNSZoneGenerator)

        # Register resources
        registry.register_resources(
            "mydns",
            "dnsb_mydns.resources",
            templates=True,    # images/templates/mydns
            rules=True,        # images/rules/mydns
            defaults=True,     # images/defaults/mydns
            controls=False,    # images/controls/mydns
            scripts=False,     # scripts/mydns
            configs=True       # configs/
        )

    def on_unload(self):
        """Cleanup when plugin is unloaded"""
        logger.info("[MyDNSPlugin] Unloading MyDNS plugin...")


# Export for entry point usage
__all__ = ['MyDNSPlugin']
```

### 2. Image Implementation

Image defines how Docker images are built.

| Base Class | Purpose |
|------|------|
| `InternalImage` | General internal image, built from templates |

```python
# src/dnsb_mydns/image.py
from dnsbuilder.abstractions import InternalImage

class MyDNSImage(InternalImage):
    """MyDNS Docker image builder"""

    def _post_init_hook(self):
        """Software-specific initialization hook

        Called after the main __init__ logic, can be overridden to:
        - Customize dependency handling
        - Set base OS
        - Add default tool packages
        """
        # Example: set default OS
        if not hasattr(self, 'os') or self.os == 'ubuntu':
            self.os = "debian"
```

**Key overridable methods**:

| Method | Description |
|------|------|
| `_post_init_hook()` | Custom logic after initialization |
| `_load_defaults()` | Load default configuration |
| `_get_template_vars()` | Return Dockerfile template variables |
| `_process_rule_extras()` | Process custom rule results |

### Rule Handler Registration

`InternalImage` supports registering custom Rule Handlers for handling software-specific rule types.

#### Basic Usage

```python
from dnsbuilder.abstractions import InternalImage
from dnsbuilder.rules import RuleEntry

class CoreDNSImage(InternalImage):
    """CoreDNS image with custom rule type support"""

    @classmethod
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        # Register custom rule handlers
        cls.register_rule_handler("plugin", cls._handle_plugin)
        cls.register_rule_handler("backend", cls._handle_backend)

    @staticmethod
    def _handle_plugin(entry: RuleEntry, result: dict):
        """Handle plugin rule type - accumulate multiple values"""
        result["extras"].setdefault("plugins", []).append(entry.val)

    @staticmethod
    def _handle_backend(entry: RuleEntry, result: dict):
        """Handle backend rule type - single value"""
        result["extras"]["backend"] = entry.val

    def _process_rule_extras(self, extras: dict):
        """Process custom fields in evaluation results"""
        if "plugins" in extras:
            self.plugins = extras["plugins"]
        if "backend" in extras:
            self.backend = extras["backend"]
```

#### Rule File Example

```json
// images/rules/coredns
[
    { "range": "[1.8.0, 1.11.99]", "set": "valid" },
    { "range": ">= 1.9.0", "val": "22.04", "set": "base" },
    { "range": ">= 1.8.0", "val": "prometheus", "set": "plugin" },
    { "range": ">= 1.8.0", "val": "cache", "set": "plugin" },
    { "range": ">= 1.9.0", "val": "etcd", "set": "backend" }
]
```

#### API Description

| Method | Description |
|------|------|
| `register_rule_handler(set_type, handler)` | Register a custom rule handler |
| `get_rule_handlers()` | Get all registered handlers |
| `_process_rule_extras(extras)` | Process evaluation results (overridable) |

**Handler Signature**:

```python
def handler(entry: RuleEntry, result: dict) -> None:
    """
    Args:
        entry: Matched rule entry, containing range, set, val fields
        result: Evaluation result dict, modify result["extras"] to store custom results
    """
```

**Inheritance Behavior**:

- Subclasses inherit handlers from parent classes
- New handlers registered by subclasses do not affect parent classes
- Handlers of different Image subclasses are isolated from each other

```python
class ParentImage(InternalImage):
    pass

ParentImage.register_rule_handler("feature", lambda e, r: None)

class ChildImage(ParentImage):
    pass

# ChildImage automatically inherits the "feature" handler
# ParentImage's handlers are not affected by ChildImage
```

- BIND Image: Built-in implementation in `src/dnsbuilder/bases/images/`

### 3. Behavior Implementation

Behavior defines the behavioral patterns of DNS servers.

| Base Class | Purpose |
|------|------|
| `Behavior` | Base behavior class, requires implementing the `generate()` method |
| `MasterBehavior` | Authoritative zone behavior, automatically handles record generation |
| `ForwardBehavior` | Forward behavior (if available) |

#### MasterBehavior Example

When inheriting `MasterBehavior`, simply implement the `generate_config_line()` method:

```python
# src/dnsb_mydns/behavior.py
from dnsbuilder.abstractions import MasterBehavior, BehaviorArtifact
from dnsbuilder.datacls.contexts import BuildContext

class MyDNSMasterBehavior(MasterBehavior):
    """MyDNS master zone behavior

    Parses behavior DSL: "example.com master www A 3600 1.2.3.4"
    """

    def generate_config_line(self, zone_name: str, file_path: str) -> str:
        """Generate zone configuration line

        Args:
            zone_name: Zone name
            file_path: Zone file path
        """
        return f'zone "{zone_name}" {{ file "{file_path}"; }};'

    def generate(self, service_name: str, build_context: BuildContext) -> BehaviorArtifact:
        """Generate behavior artifact

        The MasterBehavior base class already handles generation of most record types,
        subclasses typically only need to implement generate_config_line().
        """
        # Call parent method to generate records
        artifact = super().generate(service_name, build_context)

        # Additional processing logic can be added here
        return artifact
```

#### ForwardBehavior Example

```python
# src/dnsb_mydns/behavior.py
from dnsbuilder.abstractions import Behavior, BehaviorArtifact
from dnsbuilder.datacls.contexts import BuildContext

class MyDNSForwardBehavior(Behavior):
    """MyDNS forward behavior"""

    def __init__(self, zone: str, targets: list):
        super().__init__(zone, targets)
        # targets is a list of target servers

    def generate(self, service_name: str, build_context: BuildContext) -> BehaviorArtifact:
        """Generate forward configuration"""
        # Resolve target IPs
        resolved_ips = self.resolve_ips(self.targets, build_context, service_name)

        # Generate configuration lines
        config_line = f"forward-zone:\n"
        config_line += f"    name: {self.zone}\n"
        config_line += f"    forward-addr: {' '.join(resolved_ips)}"

        return BehaviorArtifact(config_line=config_line)

    @staticmethod
    def resolve_ips(targets, build_context, service_name):
        """Resolve target IPs (service names or IP addresses)"""
        import ipaddress
        resolved = []
        for target in targets:
            try:
                ipaddress.ip_address(target)
                resolved.append(target)
            except ValueError:
                # Not an IP, assume it's a service name
                ip = build_context.service_ips.get(target)
                if ip:
                    resolved.append(ip)
        return resolved
```
- CoreDNS behavior: `test/plugins/dnsb_coredns/__init__.py`

### 4. Includer Implementation

Includer is responsible for assembling configuration fragments into the main configuration file. There are two implementation patterns:

#### Inheriting BaseIncluder

Suitable for software with traditional include directive mechanisms (such as BIND, Unbound). Simply implement the `inject()` method:

```python
# src/dnsb_mydns/includer.py
from typing import List, Tuple
from dnsbuilder.abstractions import BaseIncluder

class MyDNSIncluder(BaseIncluder):
    """MyDNS configuration include handler (traditional include pattern)

    include_tpl is obtained from MyDNSSection (e.g. 'include "{path}";')
    """

    def inject(self, content: str, section: str, lines: List[str]) -> Tuple[str, bool]:
        """
        Inject content into an existing block.

        If the software supports block injection (e.g. BIND via bracket counting),
        return (modified_content, True).

        If not supported (e.g. Unbound has no explicit end marker),
        return (original_content, False), and BaseIncluder will automatically create a new block.

        Args:
            content: Current configuration file content
            section: Section name to inject into
            lines: List of include statements to inject
        """
        # If injection is not supported, return False directly
        return content, False
```

**BaseIncluder Workflow**:

1. For the `global` section: directly append include to main configuration
2. For `repeatable=True` sections: create new block and append
3. For `repeatable=False` sections:
   - Call `inject()` to attempt injection into an existing block
   - If injection fails, create new block and append

#### Inheriting Includer

Suitable for software without traditional include mechanisms (such as CoreDNS). Requires implementing the full `assemble()` method:

```python
# src/dnsb_mydns/includer.py
import logging
from dnsbuilder.abstractions import Includer
from dnsbuilder.datacls import ConfigFragment

logger = logging.getLogger(__name__)

class MyDNSIncluder(Includer):
    """MyDNS configuration assembler (custom assemble pattern)

    Used for software without traditional include directives, requires fully custom assembly logic.
    """

    def assemble(self) -> None:
        """
        Assemble all pending configuration fragments into the main configuration file.

        This is the core method and must be implemented by subclasses.
        Implementation should:
        1. Iterate through self.get_all_sections() to get all sections
        2. For each section, call self.get_pendings(section) to get fragments
        3. Process each fragment in a software-specific manner
        """
        if not self.main:
            logger.warning("No global main config found")
            return

        # Get all sections and their fragments
        for section in self.get_all_sections():
            fragments = self.get_pendings(section)

            for fragment in fragments:
                self._process_fragment(fragment)

    def _process_fragment(self, fragment: ConfigFragment):
        """Process a single configuration fragment"""
        # Read generated configuration content
        content = self.fs.read_text(fragment.src)

        # Append to main configuration in a software-specific manner
        append_content = f"\n# Auto-included from {fragment.dst}\n{content}\n"
        self.fs.append_text(self.main.src, append_content)
```

**Helper methods provided by Includer base class**:

| Method | Description |
|------|------|
| `add(fragment)` | Register a ConfigFragment |
| `adds(fragments)` | Register multiple ConfigFragments |
| `get_pendings(section)` | Get pending fragments for the specified section |
| `get_all_sections()` | Get all sections with pending fragments |
| `is_repeatable(section)` | Check if a section is repeatable |
| `get_section_info(section)` | Get SectionInfo object |

- BIND style: `BindIncluder` in `src/dnsbuilder/bases/includers.py`
- CoreDNS style: `CoreDNSIncluder` in `test/plugins/dnsb_coredns/__init__.py`

### 5. Section Implementation

Section defines the configuration block structure supported by the software, including template format, parameters, and software-specific configuration:

```python
# src/dnsb_mydns/section.py
from typing import Dict
from dnsbuilder.sections import Section, SectionInfo
from dnsbuilder import constants

class MyDNSSection(Section):
    """MyDNS configuration block definition"""

    # ===== Software-specific configuration =====

    # Configuration file suffix (default uses constants.DEFAULT_CONF_SUFFIX = ".conf")
    conf_suffix: str = ".conf"

    # include statement template, {path} will be replaced with file path
    # BIND: 'include "{path}";'
    # Unbound: 'include: "{path}"'
    # Knot Resolver: "dofile('{path}')"
    include_tpl: str = 'include "{path}";'

    @classmethod
    def get_sections(cls) -> Dict[str, SectionInfo]:
        return {
            # global section (main configuration, no block wrapping)
            "global": SectionInfo(
                name="global",
                template="{content}",
                indent=0,
            ),
            # server section (can appear multiple times)
            "server": SectionInfo(
                name="server",
                template="server {\n{content}\n};",
                indent=4,
                repeatable=True,
            ),
            # zone section (requires name parameter)
            "zone": SectionInfo(
                name="zone",
                template='zone "{name}" {{\n{content}\n}};',
                indent=4,
                params={"name"},
                repeatable=True,
            ),
            # options section (can only appear once)
            "options": SectionInfo(
                name="options",
                template="options {\n{content}\n};",
                indent=4,
                repeatable=False,
            ),
            # acl section (requires name parameter, repeatable)
            "acl": SectionInfo(
                name="acl",
                template='acl "{name}" {{\n{content}\n}};',
                indent=4,
                params={"name"},
                repeatable=True,
            ),
        }
```

**Section class attributes**:

| Attribute | Type | Description |
|------|------|------|
| `conf_suffix` | str | Configuration file suffix, default `.conf` |
| `include_tpl` | str | Include statement template, used by Includer |

**SectionInfo key attributes**:

| Attribute | Type | Description |
|------|------|------|
| `name` | str | Block name |
| `template` | str | Format template, must contain `{content}` |
| `indent` | int | Content indentation in spaces, default 4 |
| `params` | Set[str] | Required parameter name set |
| `repeatable` | bool | Whether it can appear multiple times, default False |
| `wrap_re` | str | Custom regex for locating a block (optional) |
| `block_pattern` | str | Property that returns the regex used to locate a block (auto-generated or uses wrap_re) |

**block_pattern Description**:

`block_pattern` is a property used by Includer to locate blocks in the configuration file:
- For the `global` section, returns `None` (no block to locate)
- For other sections:
  - If `wrap_re` is provided, uses the custom regex
  - Otherwise, auto-generates a regex from `template`

For example:
- `template="options {{\n{content}\n}};"` auto-generates `block_pattern = r'options\s*\{'`
- `template='acl "{name}" {{\n{content}\n}};'` auto-generates `block_pattern = r'acl\s+"[^"]*"\s*\{'`

**Configuration File Path Syntax**:

Users can specify section and parameters via paths:

```yaml
volumes:
  # Suffix format: named.conf.options -> section = "options"
  - ./options.conf:/etc/named.conf.options

  # Fragment format: use # to specify section
  - ./server.conf:/etc/named.conf#server

  # With parameters format: ?name=value to specify parameters
  - ./example.conf:/etc/zones.conf?name=example.com#zone
```

### 6. Zone Generator (Optional)

Used for custom zone file formats. The default uses BIND format; plugins can register custom formats:

```python
# src/dnsb_mydns/zone.py
import time
from typing import List, Optional, Dict, Any
from dnslib import RR, SOA, A, NS, QTYPE, CLASS

from dnsbuilder.builder.zone import ZoneGenerator
from dnsbuilder.datacls import BuildContext
from dnsbuilder.datacls.artifacts import ZoneArtifact

class MyDNSZoneGenerator(ZoneGenerator):
    """MyDNS custom zone file format

    Inherits ZoneGenerator base class, overrides generate() method
    to implement a custom zone file format.
    """

    def generate(self) -> List[ZoneArtifact]:
        """
        Generate zone file artifacts.

        Returns:
            List of ZoneArtifact, containing zone file content
        """
        # Generate SOA record
        serial = int(time.time())
        ns_name = f"{self.service_name}.servers.net."

        # Generate custom format zone file
        lines = []

        # SOA record (custom format)
        lines.append(
            f"SOA {self.zone.fqdn} {ns_name} admin.servers.net. "
            f"{serial} 7200 3600 1209600 3600"
        )

        # NS records
        lines.append(f"NS {self.zone.fqdn} {ns_name}")

        # User records
        for record in self.records:
            rname = str(record.rname).rstrip('.')
            rtype = QTYPE.get(record.rtype, f"TYPE{record.rtype}")
            rdata = record.rdata.toZone()
            lines.append(f"{rtype} {rname} {record.ttl} {rdata}")

        content = "\n".join(lines)

        return [
            ZoneArtifact(
                filename=f"{self.zone.label}.zone",
                content=content,
                container_path=f"/usr/local/etc/zones/{self.zone.label}.zone",
                is_primary=True
            )
        ]
```

**ZoneGenerator key attributes**:

| Attribute | Description |
|------|------|
| `context` | BuildContext object |
| `zone` | ZoneName object, containing `fqdn`, `label`, `filename`, etc. |
| `ip` | Service IP address |
| `service_name` | Service name |
| `records` | RR record list |
| `enable_dnssec` | Whether DNSSEC is enabled |

**Practical Example References**:
- BIND format: `ZoneGenerator` in `src/dnsbuilder/builder/zone.py`
- AXDNS format: `dnsb_axdns/src/dnsb_axdns/zone.py`

## Resource Files

### templates/{software}

Dockerfile template (Jinja2 format):

```dockerfile
# images/templates/mydns
FROM {{ base_image }}

# Install dependencies
RUN apt-get update && apt-get install -y \
    {% for dep in dependencies %}
    {{ dep }} \
    {% endfor %}
    && rm -rf /var/lib/apt/lists/*

# Install MyDNS
RUN wget {{ download_url }} && \
    tar xzf mydns-{{ version }}.tar.gz && \
    cd mydns-{{ version }} && \
    ./configure && make && make install

# Copy configuration
COPY {{ config_file }} /etc/mydns/mydns.conf

CMD ["mydns", "-g"]
```

### rules/{software}

Version to base image mapping (JSON format):

```json
{
    "1.0.0": "ubuntu:20.04",
    "[1.0.0, 2.0.0]": "ubuntu:22.04",
    "2.0.0": null
}
```

Rule description:
- `"version": "base_image"` — Specify that a version uses the given base image
- `"[min, max]": "base_image"` — Versions within the range use the given base image
- `"version": null` — The version is supported

### defaults/{software}

Default dependencies and tool packages (JSON format):

```json
{
    "default_deps": [
        "build-essential",
        "libssl-dev"
    ],
    "default_utils": [
        "vim",
        "dnsutils",
        "tcpdump"
    ]
}
```

Field description:
- `default_deps` — Build-time dependency packages
- `default_utils` — Runtime tool packages

## Plugin Loading Methods

Plugins are automatically discovered and loaded in the following order:

1. **Entry points** — Automatically discover plugins declared in installed packages
2. **Configuration file** — Load plugins specified by the user in config.yml
3. **Environment variable** — Load plugins specified by `DNSB_PLUGINS`

### 1. Entry Points (Recommended Publishing Method)

Declare entry points in `pyproject.toml`; plugins will be automatically discovered after installation:

```toml
[project.entry-points."dnsb.plugins"]
mydns = "dnsb_mydns:MyDNSPlugin"
```

**Notes**:
- Plugins declared via entry points are automatically discovered by DNSBuilder after package installation
- No need to specify again in config.yml or environment variables
- Suitable for plugin packages published to PyPI

### 2. Configuration File (Local Development / Unpublished Plugins)

Specify plugins not published via entry points in `config.yml`:

```yaml
plugins:
  - "dnsb_mydns:MyDNSPlugin"      # Format: module.path:ClassName
  - "my_local_plugin"              # Auto-discover Plugin subclass in module
```

**Notes**:
- Suitable for plugins in local development
- Suitable for private plugins not intended for PyPI publication
- Format supports `"module.path:ClassName"` or `"module.path"` (auto-discovery)

### 3. Environment Variable

```bash
export DNSB_PLUGINS="dnsb_mydns:MyDNSPlugin,another_plugin:AnotherPlugin"
```

**Notes**:
- Multiple plugins are separated by commas
- Suitable for temporary testing or CI/CD environments

### Loading Priority

When the same plugin is specified through multiple methods:
- Loaded in discovery order; first discovered takes priority
- Later discovered plugins with the same name are skipped
- Final loading order is determined by the `priority` attribute after sorting

## Extension Constants (attributes)

The `attributes` class attribute of a plugin is used to extend DNSBuilder's global constants at load time, using the same merge logic as `.dnsbattribute` files.

### Merge Strategy

| Type | Merge Strategy | Description |
|------|----------|------|
| dict | Deep merge | Recursively merge dicts, preserving existing key-value pairs |
| list | Extend | Append new elements to the end of the list |
| Other | Replace | Directly overwrite old value with new value |

### Extendable Constants

| Constant Name | Type | Description |
|--------|------|------|
| `RECOGNIZED_PATTERNS` | dict | Regex patterns for identifying DNS software |
| `LOG_ALIAS_MAP` | dict | Log module name aliases |
| `SUPPORTED_OS` | list | List of supported operating systems |
| `DEFAULT_OS` | str | Default operating system |
| `BASE_PACKAGE_MANAGERS` | dict | Base package manager configuration |
| `SOFT_PACKAGE_MANAGERS` | dict | Software package manager configuration |
| `ALIAS_MAP` | dict | Configuration field alias mapping |
| `KNOWN_PROTOCOLS` | set | Known path protocols |
| `BEHAVIOR_TYPES` | set | Supported behavior types |

### Constant Details

#### RECOGNIZED_PATTERNS

Defines how to identify DNS software types from image names:

```python
attributes = {
    "RECOGNIZED_PATTERNS": {
        "mydns": [
            r"\bmydns\b",           # Match mydns
            r"\bmy-dns\b",          # Match my-dns
            r"\bmydns\d",           # Match mydns1, mydns2, etc.
        ]
    }
}
```

#### BASE_PACKAGE_MANAGERS

Add new base package managers (for different operating systems):

```python
attributes = {
    "BASE_PACKAGE_MANAGERS": {
        "pacman": {
            "supported_os": ["arch"],
            "check_cmd": "command -v pacman >/dev/null 2>&1",
            "install_cmd": "pacman -Sy --noconfirm {packages}",
            "cleanup_cmd": "pacman -Sc --noconfirm"
        }
    },
    "SUPPORTED_OS": ["arch"]  # Also add supported operating system
}
```

#### SOFT_PACKAGE_MANAGERS

Add new software package managers (such as pip, npm, etc.):

```python
attributes = {
    "SOFT_PACKAGE_MANAGERS": {
        "uv": {
            "check_cmd": "command -v uv >/dev/null 2>&1",
            "install_cmd": "uv pip install {packages}",
            "cleanup_cmd": "",
            "base_requirements": {
                "apt": ["uv"],
                "apk": None  # Not supported
            }
        }
    }
}
```

### Complete Example

```python
class MyDNSPlugin(Plugin):
    name = "mydns"
    version = "0.0.1"

    attributes: Dict[str, Any] = {
        # Deep merge: add recognition patterns for mydns
        "RECOGNIZED_PATTERNS": {
            "mydns": [
                r"\bmydns\b",
                r"\bmy-dns\b",
            ]
        },

        # Extend list: add new behavior types
        "BEHAVIOR_TYPES": {"CustomBehavior"},

        # Replace: modify default operating system
        "DEFAULT_OS": "alpine",

        # Extend list: add supported operating systems
        "SUPPORTED_OS": ["arch", "fedora"],
    }

    def on_load(self, registry: PluginRegistry):
        # attributes are automatically merged before plugin loading
        # Register Section (configuration block definition)
        registry.register_section("mydns", MyDNSSection)
        # Register other components...
        registry.register_image("mydns", MyDNSImage)
        # ...
```

### Loading Order

Constant merging occurs before the plugin's `on_load` method is called:

1. Load DNSBuilder built-in constants
2. Load `.dnsbattribute` file (if it exists)
3. Merge each plugin's `attributes` in order sorted by `priority`
4. Call each plugin's `on_load` method


## PluginRegistry API

### Image Registration

```python
registry.register_image(
    software="mydns",           # Software identifier
    image_class=MyDNSImage,     # Image class
    override=False              # Whether to allow overriding existing registration
)
```

### Behavior Registration

```python
registry.register_behavior(
    software="mydns",
    behavior_type="master",      # master, forward, stub, hint, etc.
    behavior_class=MyDNSMasterBehavior,
    override=False
)
```

### Includer Registration

```python
registry.register_includer(
    software="mydns",
    includer_class=MyDNSIncluder,
    override=False
)
```

### Section Registration

```python
registry.register_section(
    software="mydns",
    section_class=MyDNSSection,
    override=False
)
```

Section class defines configuration blocks supported by the software, see [Configuration Generation Mechanism](config-generation.md).

### Zone Generator Registration

```python
registry.register_zone_generator(
    software="mydns",
    generator_class=MyDNSZoneGenerator,
    override=False
)
```

### Resource Registration

```python
registry.register_resources(
    software="mydns",
    package="dnsb_mydns.resources",
    image_templates=True, # Register resource:/images/templates/mydns
    build_templates=True, # Register resource:/builder/templates/mydns
    rules=True,        # Register resource:/images/rules/mydns
    defaults=True,     # Register resource:/images/defaults/mydns
    controls=True,     # Register resource:/images/controls/mydns
    scripts=False,     # Register resource:/scripts/mydns
    configs=True       # Register resource:/configs/
)
```

## Complete Example: CoreDNS Plugin

See the `test/dnsb_coredns/` directory for a complete runnable example

## Related Documentation

- [Dynamic Constants Configuration](dnsbattribute.md) — Runtime constant overrides
- [Resources and Templates](resources.md) — Built-in resources
- [Standard Service Templates](rule/build-templates.md) — Standard service templates