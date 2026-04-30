# Service Configuration

Used to declare the build and runtime parameters for specific services (containers). Configuration must use **dictionary format** (recommended), with each service as a key-value pair under the top-level `builds`.
To dynamically generate multiple similar services, use the `setup` phase in [Auto Automation Scripts](auto.md).

## name

- Meaning: Unique service name (i.e., the dictionary key in `builds`), used for service reference and internal resolution
- Type & Format: `string`, cannot contain colons (`:`)
- Constraint: Globally unique; duplicates or colons will cause validation errors

## image

- Required (but can be inherited from ref without explicit definition)
- Meaning: Reference to an image name, used to determine the build environment and Dockerfile generation logic
- Type & Format: `string`
- Possible values

  - Internal image names defined in `images`
  - External image names
- Constraint: When `ref` is used with the `std:` prefix, `image` must be provided
- Recommended reading

  - [External Image Configuration](external-images.md)
  - [Internal Image Configuration](images.md)

## ref*

- Optional
- Meaning: Service template or reference rule
- Type & Format: `string`; supports the following forms:

  - `std:<role>`: Standard template, needs to be resolved with the `image`'s software type as `<software>:<role>`. See [Standard Service Templates](../rule/build-templates.md)
  - `<software>:<role>`: Explicitly specify software and role, e.g. `bind:auth`, `unbound:recursor`
  - `<service_name>`: Reference to a peer service (without colon)
- Constraint: When using `std:` prefix, `image` must be provided; circular or unknown references will cause errors

## address*

- Optional
- Meaning: Fixed address or placeholder for the container, participates in network planning and variable substitution
- Type & Format: `string`
- Possible values

  - Valid IPv4 address conforming to [inet](top-level.md#inet) (if invalid, DNSB will automatically allocate one as reserved address ${rip}, but ${ip} still returns the original invalid address)
  - **Absence of this property means DNSB will assign**
  - **Empty string** means not participating in DNSB allocation, left for Docker to assign automatically

```yaml
inet: 10.10.0.0/24

builds:
  service:
    # Absent
    # ${ip} -> such as 10.10.0.2
    # ${rip} -> none
    # docker-compose.app_net.ipv4_address = 10.10.0.2
  service:
    # Empty string
    address: ""
    # ${ip} -> none
    # ${rip} -> none
    # docker-compose.app_net.ipv4_address = may be 10.10.0.10
  service:
    # Valid IPv4 address
    address: 10.10.0.3
    # ${ip} -> 10.10.0.3
    # ${rip} -> none
    # docker-compose.app_net.ipv4_address = 10.10.0.3
  service:
    # Invalid IPv4 address
    address: 192.168.1.123
    # ${ip} -> 192.168.1.123
    # ${rip} -> such as 10.10.0.4
    # docker-compose.app_net.ipv4_address = 10.10.0.4
```

## behavior*

- Optional
- Meaning: Service behavior script/DSL, parsed by templates and behavior classes to generate specific configuration (e.g. BIND zone definitions)
- Type & Format: `string`, supports multi-line text
- Further reading: See [Behavior DSL](../rule/behavior-dsl.md)

## mixins*

- Optional (not recommended, behaves similarly to multiple inheritance)
- Meaning: Additional template fragments or behavior collections, used to overlay configuration on top of base templates
- Type & Format: `string[]`; currently supports `std:<mixin_name>` format
- Constraint: Custom non-`std:` prefix mixins are not supported

## build*

- Optional
- Meaning: Whether to participate in build output
- Type & Default: `boolean`, default `true`
- Effect: Services with `false` will not generate artifacts and will not be assigned network addresses

## files*

- Optional
- Meaning: Additional file write mapping, used to generate configuration or scripts during container build
- Type & Format: `dict<string, string>`; keys are container target paths, values are content

## volumes*

- Optional
- Meaning: Volume mounts, used to map resources, configuration, and data directories
- Type & Format: `string[]`;
- Disk absolute paths will not be copied; otherwise directories or files will be copied to the `service_name/contents` directory before mounting
- Recommended reading: [DNSB Path Support & File System](../rule/paths-and-fs.md)

## cap_add*

- Optional
- Meaning: Additional container capabilities
- Type & Format: `string[]`; default supported values include `NET_ADMIN`, etc.

## mirror*

- Optional
- Meaning: Service-level mirror source configuration, only effective for services using internal images
- Type & Format: `object`
- Supported fields: Same as top-level `mirror` configuration (`apt_mirror`, `pip_index_url`, `npm_registry` and their aliases)
- Priority: Service-level mirror > Image-level mirror > Global mirror
- Note: This configuration is deep-merged with other mirror configurations, used to customize mirror sources for specific services
- Further reading
  - [Top-level Configuration - mirror](top-level.md#mirror)
  - [Internal Image Configuration - mirror](images.md#mirror-optional)

## auto*
### setup*
### modify*
### post*

Use scripts to automate initialization or modification of configuration. See [Auto Automation Scripts](auto.md) for details.

## Other Compose Fields*

- Optional
- Not checked in built-in validation, ultimately passed through to `docker-compose.yml`
- Example: `command: "tail -f /dev/null"`

## Validation & Constraints Summary

- At least one of `image`, `ref`, or `auto.setup` (the ref target must contain `image`) is required; all missing will cause an error
- `std:` prefix templates must be used with `image`
- Peer service references undergo circular detection; forming a cycle or referencing non-existent services will cause errors

## Example

```yaml
builds:
  recursor:
    image: "bind"
    ref: "std:recursor"
    behavior: . hint root

  root:
    image: "bind"
    ref: "std:auth"
    behavior: |
      . master com NS tld

  tld:
    image: "bind"
    ref: "std:auth"
    behavior: |
      com master example NS sld
```

### Dynamically Generate Multiple Services

To batch generate multiple similar services (e.g. generating `sld-1`, `sld-2`, `sld-3`), use the `auto.setup` phase:

```yaml
auto:
  setup: |
    for i in range(1, 4):
      name = f"sld-{i}"
      config.setdefault('builds', {})[name] = {
        'image': 'bind',
        'ref': 'std:auth',
        'behavior': f'example.com master www A 1.2.3.{i}'
      }

builds: {}
```

See [Auto Automation Scripts](auto.md) for details.

## Further Reading
- [Configuration Processing Pipeline](processing-pipeline.md)
- [Top-level Configuration](top-level.md)
- [Internal Image Configuration](images.md)
- [External Image Configuration](external-images.md)
- [Auto Automation Scripts](auto.md)
- [Standard Service Templates](../rule/build-templates.md)
- [Behavior DSL](../rule/behavior-dsl.md)
- [File Paths & FS](../rule/paths-and-fs.md)