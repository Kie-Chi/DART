# Top-level Configuration

Used to declare project basic information, network, and the collection of images and services. Allows additional fields that are not validated.

## name

- Required
- Meaning: Project name, used to generate output directory, `Docker Compose` project name, etc.
- Type & Format: `string`, recommended to use hyphens/underscores, avoid spaces and special characters
- Possible values: Any string; no direct coupling with other properties
- Example: `name: demo`

## inet

- Required
- Meaning: Project unified IPv4 subnet, determines the Docker network segment and service address planning
- Type & Format: `IPv4Network` (e.g. `10.88.0.0/24`)
- Possible values: Valid IPv4 network segment; must be a **usable private address segment for container networks**
- Scope of effect: Used for network planning and Compose network configuration; written to `networks` block
- Example: `inet: 10.88.0.0/24`

## images*

- Optional
- Meaning: Internal image definition collection, keys are image names, values are image configurations (see [Internal Image Configuration](images.md) for details)
- Type & Structure: **Must use dictionary format**
- Possible values: See [Internal Image Configuration](images.md) for requirements
- Constraints & Validation:

  - Image names must be **unique** and cannot contain `:`; duplicates or colons will throw validation errors
  - When the value uses `ref`, it cannot contain `software`, `version`, or `from`; if not using `ref`, all three must be provided together
  - Allows `ref` references between **internal images**; circular dependencies or non-existent references will throw errors
- Further reading:

  - [Internal Image Configuration](images.md)

## builds

- Required
- Meaning: Service build configuration collection, keys are service names, values are service configurations (see [Service Configuration](builds.md))
- Type & Structure: **Must use dictionary format**
- Possible values: See [Service Configuration](builds.md) for requirements
- Constraints & Validation:

  - At least `image` or `ref` is required; both missing will cause an error
  - When `ref` uses the `std:` prefix, `image` must be provided, otherwise an error occurs
  - Allows `ref` references between peer services; circular dependencies or non-existent references will throw errors
- Further reading:

  - [Service Configuration](builds.md)

## include*

- Optional
- Meaning: Merge other configuration files during preprocessing phase, can be processed recursively
- Type & Format: `string | string[]`; supports relative paths, absolute paths, and `resource:/` resource paths
- Behavior description:

  - Each included file undergoes the same preprocessing (including `images`/`builds` expansion, template rendering)
  - Multiple includes are merged with the current configuration using deep merge strategy; current configuration keys take priority
- Example:

  ```yaml
  include:
    - resource:/includes/sld.yml
    - ./local-extra.yml
  ```

## auto*
### setup*
### modify*
### restrict*

Use scripts to automate initialization or modification of configuration. See [Auto Automation Scripts](auto.md) for details.

## mirror*

- Optional
- Meaning: Global mirror source configuration, provides default package manager mirror sources for all internal images, accelerates builds
- Type & Format: `object`
- Supported fields:
  - `apt_mirror` (aliases: `apt`, `apt_host`): Replace the `sources.list` domain for `Ubuntu`/`Debian`, e.g. `mirrors.example.com`
  - `pip_index_url` (aliases: `pip_index`, `pip`): Set `pip`'s default `index-url`, e.g. `https://pypi.example.com/simple`
  - `npm_registry` (aliases: `npm`, `registry`): Set `npm`'s `registry`, e.g. `https://registry.example.com`
  - Special value `"auto"`: Use [chsrc](https://github.com/RubyMetric/chsrc) to automatically select the fastest mirror source
- Priority: Global mirror configuration has the lowest priority and will be overridden by `mirror` in `images` configuration
- Example:

  ```yaml
  name: demo
  inet: 10.88.0.0/24
  mirror:
    apt: "mirrors.example.com"
    pip: "https://pypi.example.com/simple"
  images:
    bind:
      ref: "bind:9.18.0"
      # Inherits global mirror configuration
    custom:
      software: bind
      version: "9.18.0"
      from: "ubuntu:20.04"
      mirror:
        apt: "mirrors.example.com"  # Overrides global configuration
  ```

## Additional Fields*

- Optional
- The top-level allows additional fields not listed; these fields will not participate in validation but will **be passed through to the final Compose output**
- Note: To avoid conflicts with reserved keys, top-level reserved keys include: `name`, `inet`, `images`, `builds`, `include`, `auto`, `mirror`

## Example

```yaml
name: demo
inet: 10.88.0.0/24
images:
  bind:
    ref: "bind:9.18.0"
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
include:
  - resource:/includes/sld.yml
```

## Further Reading

- [Configuration Processing Pipeline](processing-pipeline.md)
- [Auto Automation Scripts](auto.md)
- [Internal Image Configuration](images.md)
- [External Image Configuration](external-images.md)
- [Service Configuration](builds.md)
- [File Paths & FS](../rule/paths-and-fs.md)
- [Merge & Override Rules](../rule/merge-and-override.md)