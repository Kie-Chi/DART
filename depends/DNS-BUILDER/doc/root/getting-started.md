# Getting Started

## Prepare Configuration File

Create a `demo.yml`:

```yaml
name: "demo"
inet: "10.66.66.0/24"

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

  tld:
    image: "bind"
    ref: "std:auth"
    behavior: |
      com master example NS sld

  sld:
    image: "bind"
    ref: "std:auth"
    behavior: |
      example.com master www A 1.2.3.4
      example.com master mail A 1.2.3.5
```

**Note:** This configuration file generates a simple `root -> tld -> sld` DNS service environment, simulating the real-world process of querying `*.example.com`.

## Run Build

```bash
dnsb build demo.yml [--debug]
```

**Output:** A complete `docker-compose` project can be found at `output/demo` in the run directory.

## Start Environment

Start using DNSBuilder CLI:

```bash
# Method 1: Build and start
dnsb run demo.yml -d

# Method 2: Manual start
cd output/demo
docker compose up --build -d
```

## Manage Containers

```bash
# View status
dnsb ps demo.yml

# View logs
dnsb logs demo.yml -f

# Enter container
dnsb shell demo.yml sld

# Restart service
dnsb restart demo.yml sld

# Stop and clean up
dnsb down demo.yml
```

For more commands, see [CLI Command Reference](../cli.md)

## References

- Learn [CLI Command Reference](../cli.md) for all available commands
- Learn about [Configuration Processing Pipeline](../config/processing-pipeline.md)
- Learn [Auto Automation Scripts](../config/auto.md) usage
- See [Configuration Reference](../config/index.md) for all available options
- Explore [DNSSEC Support](../dnssec.md) for automatic signing features

## Common Options

| Command | Description |
|------|------|
| `dnsb build` | Build project configuration |
| `dnsb run -d` | Build and start in background |
| `dnsb up -d` | Start already-built project |
| `dnsb down -c` | Stop and clean images |
| `dnsb shell SERVICE` | Enter container shell |
| `dnsb logs -f` | View logs in real-time |

| Option | Description |
|------|------|
| `--debug` | Output detailed debug logs |
| `-i, --incremental` | Enable incremental build cache |
| `-w, --workdir` | Specify working directory (`@config` for config file directory) |
| `-g, --graph <file>` | Generate network topology map (Graphviz format) |
| `--vfs` | Use virtual file system instead of local disk |