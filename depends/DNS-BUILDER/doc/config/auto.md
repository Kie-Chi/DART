# Automation Scripts

Used to automatically execute Python scripts at various stages of configuration construction, enabling dynamic configuration generation, modification, and validation. Supports global scripts and service-level scripts; scripts can be executed serially or in parallel.

## Overview

The Auto feature manages configuration through three execution phases:

1. **setup**: Initialization phase, pre-executed before configuration parsing, used to generate base configuration or add new services
2. **modify**: Modification phase, executed after configuration parsing (after `ref` expansion and built-in variable substitution), used to dynamically adjust the parsed configuration
3. **restrict** (out-of-date): Validation phase, executed after configuration is fully parsed, used to check configuration validity
4. **post**: Execute arbitrary operations after the build, can perform cleanup work or even modify project content in output_dir

## Configuration Structure

### Global Automation Scripts

Declare an `auto` block in the top-level configuration:

```yaml
name: demo
inet: 10.88.0.0/24

auto:
  setup: |
    # Python code, can modify or add config content
    if 'custom_key' not in config:
      config['custom_key'] = 'custom_value'

  modify: |
    # Python code, executed after all ref resolution
    for svc_name, svc_config in config.get('builds', {}).items():
      svc_config['custom_field'] = 'modified'

  restrict: |
    # Python code, validate configuration validity
    result = "PASS"  # Must assign to result as validation outcome
    if not config.get('inet'):
      result = "ERROR: Missing inet"

  post: |
    output_dir = workdir / "output" / "recursor" / "content"
    Path(output_dir).chmod(0o755)

builds:
  recursor:
    image: "bind"
    ref: "std:recursor"
```

### Service-level Automation Scripts

Declare an `auto` block in each service configuration:

```yaml
builds:
  my_service:
    image: "bind"
    ref: "std:auth"

    auto:
      setup: |
        # Initialize this service's configuration
        config['behavior'] = '. master com NS tld'

      modify: |
        # Modify this service's configuration
        config['cap_add'] = ['NET_ADMIN']

      restrict: |
        # Validate this service's configuration
        if 'behavior' not in config:
          result = "ERROR: Missing behavior"
        else:
          result = "PASS"
```

## Script Format

### Single Script

Script content is written directly as a string:

```yaml
auto:
  setup: |
    config['new_service'] = {'image': 'bind', 'ref': 'std:recursor'}
```

### Multiple Scripts

Use a list to execute multiple scripts serially:

```yaml
auto:
  setup:
    - |
      config['builds'] = {}
    - |
      config['builds']['s1'] = {'image': 'bind', 'ref': 'std:auth'}
    - |
      config['builds']['s2'] = {'image': 'bind', 'ref': 'std:recursor'}
```

Supports explicit format (although currently all scripts are Python):

```yaml
auto:
  modify:
    - content: |
        config['builds']['s1']['cap_add'] = ['NET_ADMIN']
      type: python
    - content: |
        config['builds']['s2']['cap_add'] = ['NET_ADMIN']
      type: python
```

## Execution Environment

Each script executes in an isolated environment with access to the following global variables:

| Variable | Type | Description |
|-------|------|------|
| `config` | `dict` | Current configuration dictionary (global scripts receive the full config, service-level scripts receive that service's config) |
| `service_name` | `str` \| `None` | Current service name (`None` for global scripts, the corresponding service name for service-level scripts) |
| `result` | `Any` | Used only by `restrict` scripts, stores validation result |
| `fs` | `FileSystem` | File system object, for file read/write operations |
| `workdir` | `DNSBPath` | Working directory path (chroot), can be used for relative path operations, compatible with `pathlib.PurePosixPath` (can pass workdir directly as constructor argument to pathlib.Path) |

### Variable Usage Example

```python
# Read file
content = fs.read_text('resource:/configs/example.conf')

# Write file
fs.write_text('temp://temp/config.txt', 'some content')

# Check path existence
if fs.exists('file:///path/to/file'):
    data = fs.read_text('file:///path/to/file')
```

### Parallel Execution
- Service-level `setup` scripts: scripts for multiple services execute **in parallel** (but multiple scripts within a single service execute serially)
- Service-level `modify` scripts: scripts for multiple services execute **in parallel** (but multiple scripts within a single service execute serially)
- `restrict` scripts: all scripts execute **in parallel**


## Examples

### 1. Dynamic Service Generation

```yaml
auto:
  setup: |
    # Dynamically generate multiple recursive services based on configuration
    base_name = "recursor"
    for i in range(3):
      name = f"{base_name}_{i}"
      config.setdefault('builds', {})[name] = {
        'image': 'bind',
        'ref': 'std:recursor',
        'behavior': '. hint 8.8.8.8'
      }
```

### 2. Conditional Configuration Modification

```yaml
auto:
  modify: |
    # Inject additional parameters for all services based on image type
    for svc_name, svc_config in config.get('builds', {}).items():
      image_name = svc_config.get('image', '')
      if 'bind' in image_name:
        svc_config.setdefault('cap_add', []).append('NET_ADMIN')
```

### 3. Configuration Integrity Validation

```yaml
auto:
  restrict: |
    # Validate that all services have behavior definitions
    errors = []
    for svc_name, svc_config in config.get('builds', {}).items():
      if not svc_config.get('behavior'):
        errors.append(f"Service '{svc_name}' missing 'behavior'")

    if errors:
      result = "ERROR: " + "; ".join(errors)
    else:
      result = "PASS"
```

### 4. Generate Behavior Script (Service-level)

```yaml
builds:
  auth_server:
    image: "bind"
    ref: "std:auth"

    auto:
      setup: |
        # Generate behavior based on service-level parameters
        zone_name = config.get('zone_name', 'example.com')
        config['behavior'] = f"{zone_name} master www A 1.2.3.4"
```

## Constraints & Limitations

### Setup Phase Constraints

- After the `setup` phase executes, the system automatically performs `ref` resolution
- New services can inherit `auto.setup` from their `ref` template
- New services whose `ref` target contains `auto.setup` may still have issues (pending fix, currently unsupported)

### Modify Phase Constraints

- The `modify` phase **prohibits** using the `include` field in global configuration
- The `modify` phase **prohibits** using the `ref` field in service configuration
- These two restrictions are to avoid re-parsing after modifications, ensuring determinism of the entire build process

### Script Execution Error Handling

- Script execution exceptions will cause the entire build to fail
- Error messages will be output in logs, including script location and exception details
- Use the `--debug` flag for more detailed log information

## Recommendations

1. **Use setup for initialization**: In scenarios that don't require ref resolution, use `setup` to generate initial configuration
2. **Use modify for fine-tuning**: After all refs are resolved, use `modify` for final adjustments
3. **Use restrict for validation**: Before building, use `restrict` to check configuration validity and completeness
4. **Avoid overly complex scripts**: Scripts should remain concise; complex logic should be split into multiple scripts
5. **Leverage parallel execution**: Service-level scripts execute in parallel automatically, no manual optimization needed


## Further Reading

- [Configuration Processing Pipeline](processing-pipeline.md)
- [Configuration Overview](index.md)
- [Top-level Configuration](top-level.md)
- [Service Configuration](builds.md)
- [Internal Image Configuration](images.md)