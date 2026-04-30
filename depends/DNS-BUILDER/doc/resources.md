# Resources & Templates

DNSBuilder provides a set of built-in resources and templates located in the read-only `resource:/` file system. You can reference them in `include`, `builds.volumes`, `builds.files`, standard service templates, etc., to quickly set up common scenarios

## Reference Methods

- Use `resource:/...` paths to reference built-in resources, for example:
  - `resource:/includes/monitor.yml`
  - `resource:/configs/bind_recursor_base.conf`
  - `resource:/images/controls/unbound`
- Include in `include`:
  ```yaml
  include:
    - resource:/includes/sld.yml
    - resource:/includes/traffic.yml
  ```
- Mount or write in `volumes`/`files`:
  ```yaml
  builds:
    recursor:
      volumes:
        - "resource:/configs/unbound_recursor_base.conf:/usr/local/etc/unbound/unbound.conf"
        - "resource:/images/controls/unbound:/usr/local/var/unbound:rw"
      files:
        "/usr/local/etc/start.sh": "#!/bin/sh\nexec named -g"
  ```

For more path and file system rules, see [File Paths & FS](rule/paths-and-fs.md)

## Directory Structure Overview

The built-in resource repository is located at `src/dnsbuilder/resources`, organized into the following subdirectories by purpose:

- `includes/`: Configuration snippets (YAML) that can be directly `include`d
  - `sld.yml`: Example containing standard template combinations and behavior DSL for Root/TLD/SLD/Recursor
  - `monitor.yml`: Monitoring stack (InfluxDB, cAdvisor, Grafana), depends on `traffic.yml` (not yet fully refined)
  - `traffic.yml`: Traffic collection/statistics images and service definitions
  - `analyze.yml`: Analysis script execution example
  - `diy-auth.yml`: Custom authoritative service example
- `configs/`: Base configuration file templates
  - `bind_auth_base.conf`: BIND authoritative server base configuration
  - `bind_forwarder_base.conf`: BIND forwarder base configuration
  - `bind_recursor_base.conf`: BIND recursive resolver base configuration
  - `unbound_forwarder_base.conf`: Unbound forwarder base configuration
  - `unbound_recursor_base.conf`: Unbound recursive resolver base configuration
- `images/`
  - `controls/`: Control files and keys (mounted with `traffic`)
    - `bind/`: `rndc.key`
    - `unbound/`: `control.conf`, `unbound_control.key/.pem`, `unbound_server.key/.pem`
  - `templates/`: Standard service templates (organized by software)
    - Template snippets stored in directories such as `bind`, `unbound`, `python`, `judas`
  - `rules/`: Image rule definitions (organized by software)
- `builder/templates`: Aggregated definitions (JSON) of standard service templates, used during `std:<role>`/`<software>:<role>` resolution
- `scripts/`
  - `configs/supervisord.conf`: Process management configuration
  - `py/`: Python scripts
    - `bind.py`, `unbound.py`: DNS service-related operations/examples
    - `stat.py`, `trace.py`: Statistics and tracing
    - `none.py`: Example placeholder script
  - `sh/`: Shell scripts
    - `pcap.sh`, `recv.sh`, `stat.sh`, `trigger.sh`: Packet capture, receiving, statistics, trigger and other utility scripts

### Mounting Requirements for Include Templates

To avoid validation errors or runtime issues when using `include` to import resources, the following explicitly lists the "required mount items" and "optional mount items" for each built-in `includes/*.yml`. Here `${required}` indicates that the placeholder must be overridden with a concrete value during actual use, otherwise a validation error will be triggered

- `sld.yml`
  - Required mount items: None (depends on standard service templates `std:auth/std:recursor` to automatically mount corresponding `resource:/configs/*` and control files)
  - Optional mount items: Can append custom `volumes`/`files`, for example adding extra configuration snippets for `bind`/`unbound`
- `monitor.yml`
  - Required mount items: No explicitly required items;
  - Optional mount items: Can override or supplement `ports`, `environment`, `volumes` and other Compose fields as needed
- `traffic.yml`
  - Required mount items:
    - Also requires environment variables:
      - `ANAME` (authoritative domain name or service name being tested)
      - `RNAME` (recursive service name)
  - Optional mount items: Can add extra scripts or adjust `FILTER` (pcap filter expression)
- `analyze.yml`
  - Required mount items: `${required}:/usr/local/etc/analyze.py` (analysis script)
  - Optional mount items: Can append data files or result output directories
- `diy-auth.yml`
  - Required mount items: `${required}:/usr/src/judasdns/config.json` (Judas authoritative service configuration)
  - Optional mount items: Can append custom scripts, log directories, etc.
- `cadvisor.yml`
  - Required mount items: No explicitly required items
  - Optional mount items: Can adjust port `8080:8080` or add read-only mounts

### Script Usage and Instructions

- `pcap.sh`
  - Purpose: Automatically selects the matching network interface based on `INET`, uses `supervisord` to start packet capture and logging processes, facilitating continuous DNS traffic collection
  - Required environment: `INET` (CIDR, e.g. `10.88.0.0/24`); optional `FILTER` (default `udp and port 53`)
  - Entry point: Executed as the container startup command in the `monitor:traffic` template
- `stat.sh`
  - Purpose: Based on `tcpdump` line stream, counts packet quantity and total size by millisecond intervals, outputting real-time reports
  - Optional environment: `USED_IFACE` (default `any`), `FILTER` (default `udp and port 53`), `POLL_GAP` (default `500`ms)
  - Usage: Suitable for lightweight real-time observation after determining the network interface and filter expression
- `recv.sh`
  - Purpose: Starts a TCP listener on the specified port (default `23456`); when it receives a plaintext `trigger` command, it triggers the execution of `/usr/local/etc/exec.sh` and returns the result
  - Running method:
    - Foreground listening: `bash /path/to/recv.sh` (if `socat` is missing, the script will attempt to install it)
    - As a handler: `echo trigger | socat TCP:HOST:23456 -` or use `socat` in `EXEC` mode to call the script's `--handle` branch
  - Convention: Pre-place `exec.sh` with executable permissions on the target host (e.g., to execute an attack or test procedure once)
- `trigger.sh`
  - Purpose: Sends a trigger command to a remote listener, commonly used in conjunction with `recv.sh` to achieve "remote triggering of local scripts"
  - Required environment: `ATTACKER` (target host address or container name); optional: `TIMEOUT` (default `5` seconds)
  - Usage example:
    - Execute on source host: `ATTACKER=attacker-host bash /path/to/trigger.sh`
    - Expected behavior: The script uses `nc` to connect to `${ATTACKER}:23456` and sends the string `trigger`; if the remote `recv.sh` receives it and executes `exec.sh`, it will return `OK` or an error message.
  - Troubleshooting:
    - Check whether environment variables are set (`ATTACKER`)
    - Confirm that the target host is running `recv.sh` and the firewall allows port `23456`
    - Network connectivity and tool installation status (`nc`/`socat`)

## Standard Service Templates (Std Templates)

By using `ref: "std:<role>"` you can quickly declare service configurations for common roles; the system resolves them into specific templates based on the `image`'s software type (e.g., `bind`, `unbound`), equivalent to `<software>:<role>`.

- Available role examples:
  - `bind:recursor`: Recursive resolver, mounts `bind_recursor_base.conf` and necessary control files
  - `bind:auth`: Authoritative server, mounts `bind_auth_base.conf`
  - `bind:forwarder`: Forwarder, mounts `bind_forwarder_base.conf`
  - `unbound:recursor`: Recursive resolver, mounts `unbound_recursor_base.conf`
  - `unbound:forwarder`: Forwarder, mounts `unbound_forwarder_base.conf`

Usage example:

```yaml
builds:
  recursor:
    image: "bind"
    ref: "std:recursor"
  root:
    image: "bind"
    ref: "bind:auth"  # Explicit notation
```

For detailed template descriptions, see [Standard Service Templates](rule/build-templates.md)

## Example: Combining Include and Templates

Combining built-in `include` with standard templates, you can quickly set up monitoring and basic DNS services:

```yaml
include:
  - resource:/includes/traffic.yml
  - resource:/includes/monitor.yml

images:
  - name: "root"
    ref: "bind:9.18.0"

builds:
  root:
    image: root
    ref: std:auth
    behavior: |
      example.com master www A 1.2.3.4
      example.com master mail A 1.2.3.5
```

## Further Reading

- [File Paths & FS](rule/paths-and-fs.md) (path protocols, copy and write-to-disk rules)
- [Standard Service Templates](rule/build-templates.md) (role list and resolution rules)
- [Top-level Configuration](config/top-level.md) "Image Configuration" "Service Configuration" (comprehensive usage of references and includes)