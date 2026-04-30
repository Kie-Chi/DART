# File Paths and FS

Systematic explanation of DNSBuilder's path model (DNSBPath), supported protocols and URI syntax, filesystem (FS) dispatch and copy rules, and their usage and resolution in `include`, `builds.files`, `builds.volumes`, template resources, and other locations.

## Path Model: DNSBPath

- Fields and semantics:
  - `protocol`: Protocol name; local files default to `file`
  - `host`: Host portion of the URL; `file` and `resource` have no host
  - `path`: Path body; for URLs this is the `path` part of `scheme://host/path`
  - `query`/`query_str`: Query parameters, represented as a dictionary/raw string
  - `fragment`: Fragment (`#...`); for `git` this specifies the in-repository path
  - `is_origin`: Marks origin paths, preventing them from being copied and validated
- Absolute path determination: `is_absolute()` only checks whether the "path body" is absolute (starts with `/` or a Windows drive letter); URL fragments do not participate in absoluteness determination
- Stringification and reconstruction: `__str__()` reconstructs the full URI according to the protocol; `_reconstruct()` concatenates a new path while preserving the original protocol/host/query/fragment unchanged
- Copy hint: `need_copy` being true indicates that content needs to be written to the local working directory (non-`file` protocol or relative file path)

## Supported Protocols and URI Syntax

- Known protocol list: `constants.KNOWN_PROTOCOLS = {http, https, ftp, s3, gs, file, resource, temp, git}`.
- `file` (implicit or explicit):
  - Forms: `/etc/named.conf`, `./configs/base.conf`, `D:/data/file.txt`
  - Rule: Windows paths are normalized to POSIX style
- `resource:/...`:
  - Points to the built-in resource package `dnsbuilder.resources`; read-only
  - Example: `resource:/configs/bind_recursor_base.conf`
- `git://<host>/<org>/<repo>.git#<path/in/repo>?ref=<branch|tag|commit>`:
  - Fragment must specify the in-repository path; `ref` defaults to `HEAD`
  - The system maps `git://` to `https://<host>/<org>/<repo>.git` for cloning and checkout
  - Read-only; supports copy to disk (`copy2disk`)
  - Example: `git://github.com/example/dns-assets.git#configs/named.conf?ref=v1.2`
- Network protocols (`http`, `https`, `ftp`, `s3`, `gs`):
  - Can be correctly parsed by `DNSBPath`, but no handler is registered by default; direct read/write will raise `ProtocolError`
  - To use them, enable via `AppFileSystem.register_handler(protocol, GenericFileSystem(protocol))`
- `temp:`: In-memory filesystem, suitable for testing or temporary artifacts; registered by default

## Filesystem Implementation and Dispatch

- Dispatcher: `AppFileSystem` dispatches to the corresponding handler based on the path's `protocol`
  - Default registrations: `file -> DiskFileSystem`, `temp -> MemoryFileSystem`, `resource -> ResourceFileSystem`, `git -> GitFileSystem`.
  - Customization: Use `register_handler()` to add/modify protocol handlers
  - `create_app_fs(use_vfs)`: When a "pure in-memory filesystem" is needed, use `use_vfs=true` to override `file` with `MemoryFileSystem`
- Handler capabilities:
  - `DiskFileSystem`: Local disk implementation based on fsspec; provides `absolute()`, `copy()`, `copytree()`, etc.
  - `GenericFileSystem(protocol)`: Generic fsspec filesystem, suitable for network protocols
  - `ResourceFileSystem`: Read-only; reads from the resource package; supports recursive directory copy to disk (`copy2disk`)
  - `GitFileSystem`: Read-only; clones to a cache directory and checks out at the specified `ref`; supports copy to disk (`copy2disk`)

## Resolution and Base Directory

- Base directory: The directory where the main configuration file resides
- General rules:
  - `resource:/...` is resolved directly by `ResourceFS`
  - `file` with "non-absolute" paths are resolved relative to the base directory; it is recommended to write `${origin}./relative/path` to explicitly declare the origin
  - `git://...#<path>?ref=...` is cloned to a cache directory and then copied to the target location
- Related usage entry points: `include`, `builds.files`, `builds.volumes`, template rendering, etc. are all based on the above resolution and dispatch

## Copy and Disk-write Rules

- Copy determination:
  - When `DNSBPath.need_copy` is true, content must first be copied locally (e.g. `resource:`, `git:`, or relative `file`)
  - Paths with `is_origin=true` are never copied (use `${origin}` to declare the origin directory)
- Cross-filesystem copy:
  - `AppFileSystem.copy(src, dst)`: Cross-FS falls back to "read bytes + write bytes"
  - `AppFileSystem.copytree(src, dst)`: Only supports the following combinations:
    - Both `DiskFileSystem`: calls underlying `put(recursive=true)`
    - `GitFileSystem -> DiskFileSystem`: uses `gitFS.copy2disk()`
    - `ResourceFileSystem -> DiskFileSystem`: uses `resourceFS.copy2disk()`
  - Other combinations will raise `UnsupportedFeatureError`

## Usage Locations and Examples

- `include`:

  ```yaml
  include:
    - resource:/includes/sld.yml
    - ./local-extra.yml
  ```

  Note: Included files undergo the same preprocessing (comprehension, placeholder substitution, etc.) and are merged into the current configuration using deep merge rules
- `builds.files`:

  ```yaml
  builds:
    recursor:
      files:
        "/usr/local/etc/start.sh": "#!/bin/sh\nexec named -g"
  ```

  Note: The value can be either a resource path or an inline string; it is ultimately written to the target path
- `volumes`:

  ```yaml
  builds:
    grafana:
      image: "grafana/grafana"
      volumes:
        - "${origin}./grafana/contents:/var/lib/grafana"
        - "resource:/scripts/configs/supervisord.conf:/usr/local/etc/supervisord.conf"
  ```

  Note: Supports resource paths, relative paths, and absolute paths; permission markers (e.g. `:rw`) are passed through according to Compose semantics
- Copy configuration from Git to container:

  ```yaml
  builds:
    bind:
      volumes:
        - git://github.com/example/dns-assets.git#configs/named.conf?ref=v1.2:/usr/local/var/bind/named.conf
  ```

  Note: The system clones the repository to a cache directory, checks out the `ref`, and copies the specified file to the target path

## Image Paths

- Local build context (Local):

  ```yaml
  builds:
    custom-tool:
      image: "./images/custom-tool"  # Points to a directory containing a Dockerfile
      build: true
  ```

  Resolved as a local build path; requires a Dockerfile to exist

## Errors and Validation

- Unregistered protocol handler: raises `ProtocolError`
- Invalid path string: raises `InvalidPathError`
- Write to read-only FS: raises `ReadOnlyError` (e.g. `resource:`, `git:`)
- Unsupported cross-FS directory copy: raises `UnsupportedFeatureError`

## Further Reading

- [Top-level Configuration](../config/top-level.md) (Resolution and merging of `include`)
- [Service Configuration](../config/builds.md) (Path usage for `files`, `volumes`)
- [Behavior DSL](behavior-dsl.md) (Relationship with resource paths and placeholders)
- [Built-in Variables and Placeholders](builtins-and-placeholders.md) (Explanation of variables like `${origin}`)