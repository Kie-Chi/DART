# Built-in Variables and Placeholders

This document systematically introduces the built-in variables and placeholders available for substitution in DNSBuilder, their resolution rules, and error handling

## Scope of Application

- All string fields participate in variable substitution, including but not limited to: `behavior` under `builds.*`, `volumes`, `files` content, `container_name`, `command`, `environment`, etc.

## Variable Sources and Context

The substitution engine builds a "variable context" for each service, containing:

- Project level: `project.*` (such as `project.name`, `project.inet`)
- Current service level: `name`, `ip`/`address` and image-related attributes `image.*` (such as `software`, `version`, `name`)
- Cross-service level: `services.<service>.*` (can reference other services' `ip` and `image.*` attributes)
- Environment level: `env.<NAME>[:<default>]` (read from process environment; optional default value)

Note: Built-in reserved placeholders (such as `${required}`, `${origin}`) are not replaced with concrete values; they participate in validation and path semantics, see the next section

## Placeholders

- Reserved placeholders (not resolved to concrete values by the substitution engine):
  - `${required}`: Marks the value as mandatory. If this placeholder remains at the end, an error will be thrown during the validation phase
  - `${origin}`: Indicates no path existence/validity check, only used for "source paths" to skip validation (such as `${origin}./<service_name>/contents:/data`); do not use for target paths or non-path fields

## Variables

- Project-level variables:
  - `${project.name}`: Project name
  - `${project.inet}`: Project subnet string (such as `10.88.0.0/24`)
- Service-level variables:
  - `${name}`: Current service name
  - `${ip}` or `${address}`: Current service's IP address (synonymous)
  - Other **service available attributes** can also be referenced similarly
- Cross-service references:
  - `${services.<service>.ip}`: Reference the IP address of a specified service. If the service is not built or does not exist, an error will be thrown
  - `${services.<service>.image.<prop>}`: Reference an attribute of the image used by the specified service; commonly used attributes include `software`, `version`, `name`. If the service has no `image` configured or the attribute does not exist, an error will be thrown
  - Other **service available attributes** can also be referenced similarly
- Environment variables:
  - `${env.<NAME>[:<default>]}`: Read process environment variables; supports providing a default value (effective when not set). Will throw an error if no default value is provided and the variable is not set.
- File reading:
  - `${read.<path>[::<fallback>]}`: Read the contents of the file at the specified path, returned as a multiline string
  - Supports all DNSBPath protocols: `resource:/`, `file:/`, `temp:/`, etc.
  - Use `::` to separate fallback; uses fallback when the file does not exist, throws an error if no fallback is provided
  - Supports **nested fallback**: `${read ./file1.txt::${read ./file2.txt}}`

## Resolution Rules and Recursive Substitution

- The substitution engine builds a variable mapping for each service (including current service and project-level variables)
- Strings use regex matching for `${...}` form placeholders, and perform up to 10 recursive substitutions (to support nested variables)
- Unrecognized or failed variables are replaced with the string `none` and a warning log is recorded; if a default value (fallback) is provided, the default value is used

### Examples

```yaml
builds:
  traffic:
    ref: monitor:traffic
    environment:
      - "ANAME=${env.ANAME:example.com}"
      - "RNAME=${env.RNAME:recursor}"
      - "RECURSOR=${services.${environment.RNAME}.ip}"
      - "SOFTWARE=${services.${environment.RNAME}.image.software}"
```

Explanation:

- If `ANAME`/`RNAME` are not explicitly set, default values will be used; subsequently `RECURSOR`/`SOFTWARE` will be recursively substituted and resolved based on the former.
- The substitution engine recurses up to 10 levels; excessively deep or circular references will record warnings.

### Aliases and General Fallback Syntax

- Variable keys support alias normalization; common aliases include: `address->ip`, `svc/srv/s->services`, `img->image`, `proj->project`, `reference->ref`, `caps/cap->cap_add`, `vols->volumes`, `stack->software`, `ver->version`. For example, `${svc.recursor.ip}` is equivalent to `${services.recursor.ip}`.
- Except for environment variables, all variables support the general default value syntax: `${<path>:<default>}`. When `<path>` cannot be resolved, `<default>` is used; otherwise `none` is returned and a warning is recorded.

## Errors and Validation

- `${required}` not replaced by an actual value:
  - During service validation, it checks whether this placeholder still exists; if present, an error is thrown (such as `BuildDefinitionError` or `VolumeError`)
  - The value of this variable must be overridden; see relevant configuration chapters for override details
- Referencing non-existent services or attributes:
  - `${services.<service>.ip}` or `${services.<service>.image.<prop>}` returns `none` and records a warning when resolution fails during the substitution phase; if subsequent behavior/validation depends on this value, an error will be thrown at the corresponding phase
- Environment variable missing with no default: Returns `none` during substitution phase and records a warning; uses default value when one is provided
- File read failure: When `${read.<path>}` file does not exist or read error occurs, uses fallback if available, throws `BuildError` if no fallback
- Variable resolves to a complex type (dict/list): Throws `BuildError`, because string substitution only accepts scalar values

### Practical Recommendations

- To avoid YAML type ambiguity, quote values that may contain colons or spaces, e.g. `container_name: "${project.name}-grafana"`.
- `${origin}` is only used to mark "source paths" and skip existence validation and copying; do not use it for target paths or non-path fields.
- `${required}` is suitable for volume sources (`src`) or mandatory file paths; the validator will reject unreplaced placeholders during the build phase.
- Only use placeholders in string fields; for lists or dictionaries, express values as strings before substitution.
- For Windows paths, use forward slashes or escape appropriately to avoid being misinterpreted by YAML or URI parsing.

## Examples

```yaml
builds:
  cadvisor:
    ref: monitor:cadvisor
    container_name: ${project.name}-cadvisor

  diy-auth:
    image: judas
    command: ["node", "judasdns.js"]
    volumes:
      - ${required}:/usr/src/judasdns/config.json  # Required after include or ref inheritance; will throw error if not provided

  bind-root:
    image: bind
    behavior: |
      . hint root
      . forward ${services.recursor.ip}  # Cross-service IP reference

  # File reading examples
  custom-config:
    image: unbound
    files:
      header.txt: ${read.resource:/templates/header.txt}  # Read resource file
      local.conf: ${read ./my-custom.conf::default content}  # With fallback
      # Nested fallback: read file1 first, read file2 if not available
      cascade.conf: ${read ./primary.conf::${read ./backup.conf}}
      # Multi-level fallback: file1 -> file2 -> default value
      multi.conf: ${read ./first.txt::${read ./second.txt::final default}}
```

## Further Reading

- [Service Configuration](../config/builds.md)
- [Standard Service Templates](build-templates.md)
- [File Paths and FS](paths-and-fs.md)
- [Behavior DSL](behavior-dsl.md)