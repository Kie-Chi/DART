# Behavior DSL

The `behavior` field is used to describe how a DNS service works (such as forwarding, root hints, authoritative zones and records) using a concise "behavior script". The system parses the DSL and generates corresponding configuration fragments and artifacts based on the service's DNS software type (`bind` or `unbound`)

## Applicable Location and Resolution Timing

- Location: `builds.<service>.behavior`, type is `string`, supports multiline, one behavior per line
- Resolution timing: Parsed and artifact generation occurs after variable substitution is completed. It is recommended to use "service name" directly as the target in behaviors, avoiding embedding complex placeholders in behaviors

## Syntax Overview

- General format (except `master`): `<zone> <type> <target1>,<target2>,...`
  - `<zone>`: String, such as `"."` (root), `"com"`, `"example.com"`
  - `<type>`: Behavior type (see table below
  - `<target...>`: Target list, comma-separated; can be **service name** or IP
- `master` specific format: `<zone> master <rname> <rtype> [<ttl>] <target1>,<target2>,...`
  - `<zone>`: The "zone file key" this behavior belongs to, used to generate `db.<zone>` files; root zone is `"."`
  - `<rname>`: Record name, can be `@` (represents current zone), `www`, `ns1`, etc., FQDN (ending with `.`)
  - `<rtype>`: Record type, supports `A`, `AAAA`, `NS`, `CNAME`, `TXT`, etc.
  - `[<ttl>]`: Optional integer, default `3600`
  - `<targets>`: Target list; `A/AAAA` targets are IPs (or service names that can resolve to IPs), `NS/CNAME/TXT` targets are domain name strings (can contain **service names** to auto-generate Glue)

## Supported Behavior Types

- Both `bind` and `unbound` support:
  - `forward`: Forward queries for a `zone` to specified upstream (target is service name or IP)
  - `hint`: Configure "hint file" for root; only one target is supported (usually root server service name). Auto-generates and mounts hints file
  - `stub`: Configure `stub` (upstream master server list) for a `zone`
- `master`: Aggregate and generate authoritative zone files (`db.<zone>` or `db.root`), and write corresponding configuration (`type master` or `auth-zone`).

## Domain Name and FQDN Conventions

- Name normalization rules (applied to `<rname>` in `master` behaviors, and target domain names in `NS/CNAME/TXT` etc.):
  - `@` represents the root (apex) of the current Zone, e.g. when `<zone>=com`, `@` expands to `com`; for root zone `"."`, it is `"."`
  - Names ending with `.` are treated as fully qualified domain names (FQDN), kept as-is without appending Zone, e.g. `www.`
  - Names not ending with `.` are treated as relative names, and will have the current `<zone>` appended:
    - `<zone>=com`, `www` -> `www.com`
    - `<zone>="."` (root zone), `example` -> `example.`
- When the target of an `NS` record is an internal service name (rather than a domain name string), it is automatically resolved to the service IP and generates a Glue record; when the target is an external domain name, it is processed according to the above normalization rules

## Target Resolution and Validation

- Targets can be written as "service name" or "IP". Service names are resolved to the service's IP in the build context; resolution failure throws an error
- `hint` only allows one target; more than one will throw an error
- When the target of an `NS` record is an "internal service name", a Glue record is auto-generated (generates an `A` record for that target with a randomized `ns` name prefix to avoid conflicts)
- Unsupported record types or syntax errors throw "feature unsupported / format invalid" errors

## Relationship with Placeholders

- Behavior DSL itself does not introduce placeholder syntax; but the `behavior` string also participates in global variable substitution, see [Built-in Variables and Placeholders](builtins-and-placeholders.md)
- Recommended practice: Write service names or explicit IPs directly in behaviors; avoid using placeholders like `${services.<name>.ip}` within behaviors to reduce coupling

## Examples

```yaml
builds:
  recursor:
    image: bind
    ref: std:recursor
    behavior: |
      . hint root              # BIND/Unbound: root hint, target is service name "root"

  root:
    image: bind
    ref: std:auth
    behavior: |
      . master @ NS tld        # Write NS record in root zone, target is service name "tld" (auto-generate Glue)
      com master www A 1.2.3.4 # Write A record in com zone
      com master mail A 1.2.3.5

  forwarder:
    image: unbound
    ref: std:forwarder
    behavior: |
      example.com forward recursor,8.8.8.8
      . stub tld               # Configure stub for root zone, target is internal service "tld"
```

## Generated Artifacts

- Configuration fragments: Written to corresponding sections of `named.conf` or `unbound.conf` by software type (`forward-zone`/`stub-zone`/`auth-zone`/`type forward|stub|hint|master`)
- Zone files: `master` behaviors aggregate all records and generate `db.<zone>` (root zone as `db.root`), while creating volume mounts and configuration entries
- Root hints: `hint` behaviors generate `gen_<service>_root.hints` file and mount it to the corresponding path in the container

## Errors and Constraints

- Referenced non-existent service name or invalid IP: throws `BehaviorError`
- Unsupported record type or invalid syntax: throws `UnsupportedFeatureError`
- `hint` target count is not 1: throws `BehaviorError`

## Further Reading

- [Service Configuration](../config/builds.md)
- [Standard Service Templates](build-templates.md)
- [Built-in Variables and Placeholders](builtins-and-placeholders.md)