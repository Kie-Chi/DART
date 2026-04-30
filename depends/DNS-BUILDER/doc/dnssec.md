# DNSSEC Support (Experimental)

Only available on Linux environments with `bind9-utils` installed

DNSBuilder automatically supports DNSSEC signing and key management

## Features

- **Automatic Signing Chain Construction**: Automatically establishes the trust chain from root to leaf
- **Automatic Key Generation**: KSK and ZSK are automatically generated and managed
- **Automatic DS Record Propagation**: Child zone DS records are automatically added to the parent zone
- **Transparent Integration**: No manual configuration required; all DNSSEC-related tasks are handled automatically
- **DNSSEC Hooks**: Supports injecting custom scripts during the signing process, for vulnerability reproduction scenarios
- **Pre-generated Key Support**: Supports using pre-generated keys, facilitating key tag control and key reuse

## Using Pre-generated Keys

Specify the directory containing pre-generated keys via the `dnssec.include` field:

```yaml
builds:
  root:
    image: bind
    dnssec:
      enable: true
      include: "resource:/keys/root"  # Key directory
```

### Key File Naming

The system scans the directory for key files in the following formats:

**Recommended format:**
```
<zone>.ksk.key       # KSK public key
<zone>.ksk.private   # KSK private key
<zone>.zsk.key       # ZSK public key
<zone>.zsk.private   # ZSK private key
```

**BIND standard format:**
```
K<zone>.+<alg>+<keytag>.key
K<zone>.+<alg>+<keytag>.private
```

The system automatically identifies KSK (flags: 257) and ZSK (flags: 256).

### Use Cases

#### 1. Controlling a Specific Key Tag

```bash
# Brute-force generate keys with a specific key tag
while true; do
  dnssec-keygen -a ECDSAP256SHA256 -n ZONE example.com
  # Check whether the generated key tag meets the requirement
done
```

#### 2. Key Reuse

Use the same set of keys across multiple builds to keep DS records unchanged:

```yaml
builds:
  root:
    image: bind
    dnssec:
      enable: true
      include: "resource:/persistent_keys/root"
```

#### 3. Simulating Key Compromise

Use known "leaked" keys for vulnerability reproduction:

```yaml
builds:
  compromised:
    image: bind
    dnssec:
      enable: true
      include: "resource:/leaked_keys/compromised"
```

### Fallback Behavior

If the `include` directory does not exist or no valid keys are found, the system will:
1. Output a warning log
2. Automatically fall back to key generation
3. Continue the normal signing process

## How It Works

### Signing Process

1. **Key Generation Phase**
   - Generate a KSK (Key Signing Key) for each zone
   - Generate a ZSK (Zone Signing Key) for each zone
   - Keys are stored in the `key:/` file system

2. **Zone Signing Phase**
   - Sign zone data using the ZSK
   - Sign the DNSKEY record set using the KSK
   - Generate signed zone files (`.signed`)

3. **Trust Chain Establishment**
   - Generate DS records from child zone KSKs
   - DS records are automatically added to the parent zone
   - Root zone configures a Trust Anchor

## DNSSEC Hooks

DNSSEC Hooks allow injecting custom Python scripts at key points in the signing process, primarily for DNS vulnerability reproduction scenarios.

### Signing Process

```
┌─────────────────────────────────────────────────────────────────┐
│                    DNSSEC Signing Process                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. First signing phase (executed independently for each zone)  │
│     ┌──────────────┐                                            │
│     │Generate zone  │                                            │
│     │    file       │                                            │
│     └──────┬───────┘                                            │
│            ↓                                                    │
│     ┌──────────────┐                                            │
│     │Write unsigned │  → temp:/services/.../db.<zone>.unsigned  │
│     └──────┬───────┘                                            │
│            ↓                                                    │
│     ┌──────────────┐                                            │
│     │   pre hook   │  ← Can modify: temp:/.../db.<zone>.unsigned│
│     └──────┬───────┘                                            │
│            ↓                                                    │
│     ┌──────────────┐                                            │
│     │  DNSSEC sign │                                            │
│     └──────┬───────┘                                            │
│            ↓                                                    │
│     ┌──────────────┐                                            │
│     │ Write key:/  │  ← Keys, DS records written to key:/ fs    │
│     │ Write signed │  → temp:/services/.../db.<zone>            │
│     └──────────────┘                                            │
│                                                                 │
│  2. Re-signing phase (establish trust chain, parent signs child │
│     zone's DS)                                                  │
│     ┌──────────────┐                                            │
│     │   mid hook   │  ← Can modify: key:/ (inject forged DS,   │
│     │              │     modify keys)                            │
│     └──────┬───────┘                                            │
│            ↓                                                    │
│     ┌──────────────┐                                            │
│     │  Re-signing  │  ← Parent zone re-signs, including child   │
│     │              │     zone's DS                               │
│     └──────┬───────┘                                            │
│            ↓                                                    │
│     ┌──────────────┐                                            │
│     │  post hook   │  ← Can modify: temp:/services/... (final   │
│     │              │     signed result)                          │
│     └──────────────┘                                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Configuration Format

```yaml
builds:
  root:
    image: bind
    ref: std:auth
    dnssec:
      enable: true
      hooks:
        pre: |
          # Modify unsigned zone content
          print(f"Zone: {zone.fqdn}")
          # unsigned_content = "modified..."

        mid: |
          # Inject forged DS records into key:/
          fake_ds = "malicious.com. IN DS 99999 13 2 DEADBEEF..."
          fs.write_text("key:/root/malicious.ds", fake_ds)

        post: |
          # Modify the final signed result
          signed_path = f"temp:/services/{service_name}/zones/{zone.filename}"
          content = fs.read_text(signed_path)
          # fs.write_text(signed_path, modified_content)
```

### Hooks Detailed Description

| Hook | Execution Timing | Modifiable Content | Execution Count |
|------|-----------------|--------------------|----------------|
| `pre` | Before individual zone signing | `temp:/services/.../db.<zone>.unsigned` (unsigned zone file) | Once per zone |
| `mid` | After all zones are signed, before re-signing | `key:/` file system (DS records, keys) | Once per zone |
| `post` | After re-signing completes | `temp:/services/...` file system (final signed result) | Once per zone |

### Available Variables

All hooks can access the following variables:

| Variable | Type | Description |
|----------|------|-------------|
| `zone` | `ZoneName` | Zone name object; `zone.fqdn` returns `example.com.`, `zone.label` returns `example.com` |
| `service_name` | `str` | Service name |
| `fs` | `FileSystem` | File system object |
| `workdir` | `DNSBPath` | Working directory path |
| `config` | `dict` | Complete configuration of the current service |

`mid` hook additional variables:
| Variable | Type | Description |
|----------|------|-------------|
| `zone_graph` | `dict` | Dependency graph of all zones |

`post` hook additional variables:
| Variable | Type | Description |
|----------|------|-------------|
| `zone_graph` | `dict` | Dependency graph of all zones |

### File System Paths

**Key storage (key:/)** — read during DNSSEC re-signing:

| Path | Purpose | Available Phase |
|------|---------|----------------|
| `key:/<service>/<zone>.ksk.key` | KSK public key | mid, post |
| `key:/<service>/<zone>.ksk.private` | KSK private key | mid, post |
| `key:/<service>/<zone>.zsk.key` | ZSK public key | mid, post |
| `key:/<service>/<zone>.zsk.private` | ZSK private key | mid, post |
| `key:/<service>/<zone>.ds` | DS record | mid, post |

**Service directory (temp:/services/)** — zone file storage:

| Path | Purpose | Available Phase |
|------|---------|----------------|
| `temp:/services/<service>/zones/db.<zone>.unsigned` | Unsigned zone file | pre, post |
| `temp:/services/<service>/zones/db.<zone>` | Signed zone file | post |

### Use Cases

#### 1. Modifying Zone Content Before Signing (pre)

```yaml
hooks:
  pre: |
    # Directly manipulate the file system to modify the unsigned zone file
    unsigned_path = f"temp:/services/{service_name}/zones/{zone.filename}.unsigned"
    content = fs.read_text(unsigned_path)
    # Shorten all TTL values
    modified = content.replace('3600', '300')
    fs.write_text(unsigned_path, modified)
```

#### 2. Injecting Forged DS Records (mid)

```yaml
hooks:
  mid: |
    # Write forged DS records
    fake_ds = "malicious.com. IN DS 99999 13 2 DEADBEEF123456..."
    fs.write_text("key:/root/malicious.ds", fake_ds)

    # Or modify existing DS files
    # existing = fs.read_text("key:/tld/com.ds")
    # fs.write_text("key:/tld/com.ds", existing + "\n" + fake_ds)
```

#### 3. Modifying the Final Signed Result (post)

```yaml
hooks:
  post: |
    # Read the signed zone file
    signed_path = f"temp:/services/{service_name}/zones/{zone.filename}"
    content = fs.read_text(signed_path)

    # Make modifications (e.g., add extra records)
    # modified = content + "\nextra.example.com. IN A 1.2.3.4"
    # fs.write_text(signed_path, modified)
```

#### 4. Key Compromise Simulation (mid)

```yaml
hooks:
  mid: |
    # Copy private key to temporary directory, simulating a leak
    ksk_private = fs.read_text(f"key:/{service_name}/{zone.label}.ksk.private")
    fs.write_text(f"temp:/leaked_keys/{zone.label}.ksk.private", ksk_private)
    print(f"[WARNING] Key leaked to temp:/leaked_keys/")
```

### Notes

1. **Execution Order**: Hooks are executed in the order pre → mid → post
2. **Error Handling**: If a hook execution fails, the entire signing process will stop
3. **Security**: Hooks have full file system access; use with caution

## Related Documentation

- [Configuration Reference](config/index.md) - Configuration file format
- [Behavior DSL](rule/behavior-dsl.md) - Zone behavior configuration
- [Auto Scripts](config/auto.md) - Automation scripts

## Reference Resources

- [DNSSEC HOWTO](https://www.dnssec-tools.org/)
- [BIND 9 DNSSEC Guide](https://bind9.readthedocs.io/en/latest/dnssec-guide.html)
- [RFC 4033](https://tools.ietf.org/html/rfc4033) - DNSSEC Introduction
- [RFC 4034](https://tools.ietf.org/html/rfc4034) - Resource Records
- [RFC 4035](https://tools.ietf.org/html/rfc4035) - Protocol Modifications