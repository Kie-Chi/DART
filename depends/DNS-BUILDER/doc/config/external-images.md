# External Image Configuration

In addition to internal images declared in the top-level `images`, services can also directly use external images. External images fall into two categories:

- DNSB Build Image (Local): `image` points to a directory path containing a `Dockerfile` (can also be fetched via DNSB protocol file system); DNSB obtains the local build during the build phase
- Docker Community Image (Remote): `image` points to a repository image name (e.g. `ubuntu:22.04`, `grafana/grafana`); pulled by Docker and used directly

## Differences from Internal Images

- Internal images: declared in the top-level `images`, support `ref`, the `software`/`version`/`from` triplet, default value handling for dependencies and tools, and participate in the "software type" inference for standard template (`std:`) resolution
- External images: not declared in `images`, used by writing a string directly in the service's `image`; do not have a "software type", so they cannot be used for `std:` role inference

## Usage Examples

### DNSB Build

```yaml
builds:
  custom-tool:
    image: "./images/custom-tool"  # Points to a directory containing a Dockerfile
    build: true
    volumes:
      - "${origin}./custom-tool/contents:/usr/local/etc"
```

Notes:

- The path can be any path supported by DNSB, see [File Paths & FS](../rule/paths-and-fs.md); relative paths are resolved relative to the main configuration file's directory
- The directory pointed to by the path should contain a `Dockerfile` and related build context files, or directly point to a `Dockerfile` file

### Docker Community

```yaml
builds:
  grafana:
    image: "grafana/grafana:latest"
    ports:
      - "3000:3000"
    volumes:
      - "${origin}./grafana/contents:/var/lib/grafana"
```

Notes:

- Must comply with Docker Compose's [image requirements](https://docs.docker.com/reference/compose-file/services/#image)
- Compose fields (such as `ports`, `environment`, `volumes`, etc.) can still be passed through

## Constraints & Notes

- `std:` templates, `behavior` and other built-in behaviors are related to the "software type", which needs to be inferred from the internal image's `software` type; therefore, external images **are not applicable**
- External images cannot be referenced by internal images

## When to Choose External Images

- Directly use community or vendor-provided images (e.g. `grafana/grafana`, `google/cadvisor`).
- Already have a user-defined, mature `Dockerfile` build context, and do not need internal image validation and template extension.

For more details on internal image declaration and constraints, see [Internal Image Configuration](images.md)

## Further Reading

- [Internal Image Configuration](images.md)
- [Service Configuration](builds.md)
- [File Paths & FS](../rule/paths-and-fs.md)