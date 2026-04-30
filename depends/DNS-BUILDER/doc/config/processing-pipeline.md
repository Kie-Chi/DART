# Configuration Processing Pipeline

This document details how DNSB processes configuration files, from loading to final output.

## Flowchart

```
Configuration File Loading
    ↓
[Preprocessing Phase] include merge → variable rendering
    ↓
[Auto Setup] Dynamic configuration generation
    ↓
[Image Initialization] Parse images block, create internal image objects
    ↓
[Ref Resolution] Resolve all ref references, inherit template configuration
    ↓
[Network Planning] Assign IPv4 addresses to services
    ↓
[Variable Substitution] Replace ${var} placeholders
    ↓
[Topology Mapping] Generate network topology map
    ↓
[Auto Modify] Modify parsed configuration
    ↓
[Build Generation] Generate Dockerfile, docker-compose.yml, etc.
    ↓
[Auto Restrict] Validate final configuration validity
    ↓
[Incremental Cache] Detect changes, only rebuild necessary services (Optional)
    ↓
Output Artifacts
```

## Phases

### 1. Configuration File Loading

**Action:** Parse YAML configuration file

```bash
dnsb config.yml
```

- Read YAML format configuration from the specified file
- Initialize `Config` object
- No validation or expansion is performed

### 2. Preprocessing Phase

**Action:** include merge and initial processing

```yaml
name: demo
inet: 10.88.0.0/24
include:
  - resource:/includes/base.yml
  - ./custom.yml
```

- Recursively process configuration files referenced by the `include` field
- Integrate multiple configurations using deep merge strategy
- Current configuration keys have the highest priority
- Initial processing of variables and resource paths

### 3. Auto Setup Phase

**Action:** Execute initialization scripts

```yaml
auto:
  setup: |
    # Can generate new services, initialize configuration
    for i in range(3):
      config['builds'][f'service-{i}'] = {...}
```

- Initialize service configuration or even the overall configuration based on script content
- Dynamically generate base services
- Initialize configuration based on external conditions
- Import configuration from external data sources

### 4. Image Initialization

**Action:** Parse the `images` block, create internal image objects

```yaml
images:
  bind:
    ref: "bind:9.18.0"
  unbound:
    software: unbound
    version: "1.19.0"
    from: "debian:12"
```

- Load each image configuration sequentially
- Create corresponding `InternalImage` or `ExternalImage` objects
- Cache image objects for subsequent ref resolution

### 5. Ref Resolution

**Action:** Resolve all service `ref` fields, inherit template configuration

```yaml
builds:
  recursor:
    image: bind
    ref: std:recursor        # ← Needs resolution
    behavior: . hint root
```


### 6. Network Planning

**Action:** Assign IPv4 addresses to each service

```yaml
inet: 10.88.0.0/24
builds:
  recursor:
    address: 10.88.0.2        # ← Manually specified
  root:                        # ← Auto-assigned
```

### 7. Variable Substitution

**Action:** Replace `${...}` placeholders in configuration

```yaml
behavior: |
  server 127.0.0.1@53 ${services.recursor.image.version}
```

### 8. Auto Modify Phase

**Action:** Execute modification scripts, adjust parsed configuration

```yaml
auto:
  modify: |
    # Executed after all ref resolution, network planning, and variable substitution
    for svc_name, svc_config in config['builds'].items():
      svc_config['cap_add'] = ['NET_ADMIN']
```

- **Prohibited from using `include` field at top level**
  - include merge must be completed before setup
- **Prohibited from using `ref` field in services**
  - ref resolution must be completed before modify

### 9. Build Generation

**Action:** Generate Dockerfile, configuration files, etc. for each service

- Generate Dockerfile based on service configuration and image type
- Generate service-specific configuration files (e.g. BIND zone files)
- Process volume mounts and file copies
- Generate `docker-compose.yml`

### 10. Auto Restrict Phase

**Action:** Execute validation scripts, check final configuration validity

```yaml
auto:
  restrict: |
    # Executed after all generation is complete, before deployment
    errors = []
    for svc_name, svc_config in config['builds'].items():
      if not svc_config.get('image'):
        errors.append(f"Service {svc_name} missing image")

    if errors:
      result = "ERROR: " + "; ".join(errors)
    else:
      result = "PASS"
```

- Validate configuration completeness and validity
- Check network connectivity requirements
- Provide pre-deployment checklist


## Further Reading

- [Auto Automation Scripts](auto.md)
- [Configuration Overview](index.md)
- [Standard Service Templates](../rule/build-templates.md)
- [File Paths & FS](../rule/paths-and-fs.md)