# Internal Image Configuration

On the basis of DNSB **internal Dockerfile templates**, declare base images or inherited images to determine the service runtime environment. Two methods are supported: referencing an existing internal image via `ref`, or providing the full base triplet.

Configuration must use **dictionary format** (recommended), with each image as a key-value pair under the top-level `images`.

External images correspond to internal images; for details, see [External Image Configuration](external-images.md)


## name

- Meaning: Unique image name (i.e., the dictionary key in `images`), used for service reference and internal resolution
- Type & Format: `string`, cannot contain colons (`:`)
- Constraint: Globally unique; duplicates or colons will cause validation errors

## ref

- Meaning: Reference to an existing image or image template (e.g. `bind:9.18.0`)
- Type & Format: `string`; supports `software:version` format or local image name (without colon)
- Possible values:
  - Built-in software types: `bind`, `unbound`, `python`, `judas` (see resource default dependencies `resources/images/defaults/{software}`)
  - Local image names in the same file: referencing peer-defined images (without colons)
- Constraint: Mutually exclusive with `software`, `version`, `from`; when using `ref`, these three must not be provided
- Resolution note: When using a local image name, it will be resolved along the inheritance chain and merged with parent config; when using `software:version`, it will be initialized with the corresponding internal image class.

## software

- Meaning: Software type (only when not using `ref`)
- Type & Possible values: `string`, common values include `bind`, `unbound`, `python`, `judas`
- Constraint: Must appear together with `version` and `from`; otherwise validation fails

## version

- Meaning: Software version (only when not using `ref`)
- Type & Format: `string`, e.g. `9.18.0`, `1.18`, etc.
- Constraint: Must appear together with `software` and `from`

## from

- Meaning: Base image name (e.g. `ubuntu:20.04`)
- Type & Format: `string`; supports Docker Hub image names
- Constraint: Must appear together with `software` and `version`; serves as the `FROM` directive in the internal image Dockerfile

## dependency

- Meaning: Build-time dependency package list, affecting packages installed during the image build phase
- Type & Format: `string[]`; e.g. `build-essential`, `libssl-dev`, etc.
- Default & Reference: Different software types have their own default dependencies, see `resources/images/defaults/{software}`

## util

- Meaning: Runtime utility package list, e.g. `dnsutils`, `tcpdump`, etc.
- Type & Format: `string[]`; can include `python3-xxx` to automatically handle Python dependencies
- Default & Reference: Different software types have their own default utility packages, see `resources/images/defaults/{software}`

## mirror*

- Optional
- Meaning: Inject custom package manager mirror sources into the internal image template to accelerate builds
- Type & Format: `object`
- Supported fields:
  - `apt_mirror`: Replace the `sources.list` domain for `Ubuntu`/`Debian`, e.g. `mirrors.example.com`
  - `pip_index_url`: Set `pip`'s default `index-url`, e.g. `https://pypi.example.com/simple`
  - `npm_registry`: Set `npm`'s `registry`, e.g. `https://registry.example.com`

Example:

```yaml
images:
  bind-fast:
    software: bind
    version: "9.18.0"
    from: "ubuntu:20.04"
    mirror:
      apt: "mirrors.example.com"
      pip: "https://pypi.example.com/simple"

  judas-fast:
    software: judas
    version: "0.0.0"
    from: "debian:10"
    mirror:
      apt: "mirrors.example.com"
      npm: "https://registry.example.com"
```

## Validation & Constraints Summary

- When using `ref`, none of `software`, `version`, or `from` may appear
- When not using `ref`, `software`, `version`, and `from` must all be provided
- Image names cannot contain colons and must be unique

## Example

```yaml
images:
  bind:
    ref: "bind:9.18.0"

  bind-fast:
    software: bind
    version: "9.18.0"
    from: "ubuntu:20.04"
    mirror:
      apt_mirror: "mirrors.example.com"

  judas-fast:
    software: judas
    version: "0.0.0"
    from: "debian:10"
    mirror:
      apt_mirror: "mirrors.example.com"
      npm_registry: "https://registry.example.com"
```

## Further Reading

- [Top-level Configuration](top-level.md)
- [Service Configuration](builds.md)
- [Merge & Override Rules](../rule/merge-and-override.md)