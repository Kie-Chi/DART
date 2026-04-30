# CLI Command Reference

DNSBuilder provides a complete command-line tool, supporting project building, container management, image cleanup, and more.

## Global Options

```bash
dnsb [OPTIONS] COMMAND [ARGS]
```

### Options

- `--debug`: Enable debug log output
- `-l, --log-levels TEXT`: Set log levels per module (e.g., `sub=DEBUG,res=INFO`)
- `-f, --log-file TEXT`: Specify log file path
- `--version`: Show version information
- `--help`: Show help information

### Examples

```bash
dnsb build config.yml -i    # Build using incremental mode
dnsb clean --all            # Clean all shared images
dnsb ui                     # Start Web UI
```

## Command List

### build

Build DNS infrastructure from a configuration file

```bash
dnsb build CONFIG_FILE [OPTIONS]
```

**Arguments:**
- `CONFIG_FILE`: Configuration file path (.yml or .yaml)

**Options:**
- `-i, --incremental`: Enable incremental build caching
- `-g, --graph PATH`: Generate network topology diagram (DOT format)
- `-w, --workdir PATH`: Working directory
  - Default: current directory
  - `@config`: directory where the configuration file is located
  - `@cwd`: explicitly use the current directory
- `--vfs`: Enable virtual file system (in-memory build)

**Examples:**
```bash
dnsb build test.yml
dnsb build test.yml -i -g topology.dot
dnsb build test.yml -w @config
```

---

### run

Build the project and start all containers (equivalent to `build` + `docker compose up`)

```bash
dnsb run CONFIG_FILE [OPTIONS]
```

**Options:**
- `-i, --incremental`: Enable incremental build
- `-g, --graph PATH`: Generate topology diagram
- `-w, --workdir PATH`: Working directory
- `--vfs`: Virtual file system
- `-d, --detach`: Run containers in the background
- `--build`: Force rebuild Docker images

**Process:**
1. Build DNS infrastructure configuration
2. Start all containers using docker compose

**Examples:**
```bash
dnsb run test.yml -d         # Run in background
dnsb run test.yml --build    # Force rebuild images
```

---

### up

Start an already-built project (skip the build step)

```bash
dnsb up CONFIG_FILE [OPTIONS]
```

**Options:**
- `-w, --workdir PATH`: Working directory
- `-d, --detach`: Run in background

**Notes:**
Suitable for scenarios where the configuration has not changed and only containers need to be quickly started

**Examples:**
```bash
dnsb up test.yml -d
```

---

### down

Stop containers and clean up resources

```bash
dnsb down CONFIG_FILE [OPTIONS]
```

**Options:**
- `-w, --workdir PATH`: Working directory
- `-v, --volumes`: Also delete volumes
- `-c, --clean`: Also delete images

**Cleanup scope:**
1. Stop and delete all containers
2. Delete project networks
3. Delete volumes (if `-v` is specified)
4. Delete images (if `-c` is specified)

**Examples:**
```bash
dnsb down test.yml           # Only stop containers
dnsb down test.yml -c        # Stop and clean up images
dnsb down test.yml -vc       # Full cleanup (including volumes)
```

---

### exec

Execute a command inside a running service container.

```bash
dnsb exec CONFIG_FILE SERVICE [COMMAND...] [OPTIONS]
```

**Arguments:**
- `SERVICE`: Service name (supports auto-completion)
- `COMMAND`: Command to execute (default: `/bin/bash`)

**Options:**
- `-w, --workdir PATH`: Working directory
- `-u, --user USER`: Specify user

**Examples:**
```bash
dnsb exec test.yml sld                    # Start bash shell
dnsb exec test.yml sld sh                 # Start sh
dnsb exec test.yml sld cat /etc/hosts     # Execute command
dnsb exec test.yml sld -u root bash       # Run as root user
```

---

### shell

Start an interactive shell in a container (shortcut for `exec`)

```bash
dnsb shell CONFIG_FILE SERVICE [SHELL_CMD] [OPTIONS]
```

**Arguments:**
- `SERVICE`: Service name
- `SHELL_CMD`: Shell command (default: `/bin/bash`)

**Examples:**
```bash
dnsb shell test.yml sld          # Start bash
dnsb shell test.yml sld sh       # Start sh
```

---

### logs

View log output of service containers

```bash
dnsb logs CONFIG_FILE [SERVICES...] [OPTIONS]
```

**Arguments:**
- `SERVICES`: List of service names (empty to show all services)

**Options:**
- `-w, --workdir PATH`: Working directory
- `-f, --follow`: Follow logs in real time
- `-t, --tail N`: Only show the last N lines

**Examples:**
```bash
dnsb logs test.yml                  # All service logs
dnsb logs test.yml sld tld          # Specific service logs
dnsb logs test.yml -f               # Real-time follow
dnsb logs test.yml sld -f -t 100    # Follow last 100 lines
```

---

### ps

Show the status of all containers in the project

```bash
dnsb ps CONFIG_FILE [OPTIONS]
```

**Options:**
- `-w, --workdir PATH`: Working directory

**Examples:**
```bash
dnsb ps test.yml
```

---

### restart

Restart one or more service containers

```bash
dnsb restart CONFIG_FILE [SERVICES...] [OPTIONS]
```

**Arguments:**
- `SERVICES`: List of service names (empty to restart all services)

**Options:**
- `-w, --workdir PATH`: Working directory

**Examples:**
```bash
dnsb restart test.yml              # Restart all services
dnsb restart test.yml sld tld      # Restart specific services
```

---

### clean

Clean up project or shared images

```bash
dnsb clean [CONFIG_FILE] [OPTIONS]
```

**Arguments:**
- `CONFIG_FILE`: Configuration file (optional)

**Options:**
- `--all`: Clean all `dnsb-*` shared images
- `-w, --workdir PATH`: Working directory

**Cleanup modes:**
1. **Project mode** (specify CONFIG_FILE): Clean images for that project
2. **Global mode** (`--all`): Clean all shared images

**Examples:**
```bash
dnsb clean test.yml       # Clean project images
dnsb clean --all          # Clean all shared images
```

---

### ui

Start the Web UI server

```bash
dnsb ui
```

**Access address:** `http://localhost:8000`

**Notes:** Provides API interface and management UI

---

## Auto-Completion

DNSBuilder CLI supports intelligent auto-completion:

### Configuration File Completion

All commands requiring `CONFIG_FILE` support auto-completion of `.yml` and `.yaml` files in the current directory:

```bash
dnsb ps <TAB>           # Shows: test.yml, prod.yml, ...
```

### Service Name Completion

`exec`, `shell`, `logs`, `restart` commands support service name completion:

```bash
dnsb shell test.yml <TAB>   # Shows: sld, tld, root, resolver, ...
```

**Note:** Auto-completion automatically filters out internal builder services (`dnsb-image-builder-*`).

### Enabling Completion

Bash/Zsh completion needs to be registered first:

```bash
# Bash
eval "$(_DNSB_COMPLETE=bash_source dnsb)"

# Zsh
eval "$(_DNSB_COMPLETE=zsh_source dnsb)"

# Permanent (add to ~/.bashrc or ~/.zshrc)
echo 'eval "$(_DNSB_COMPLETE=bash_source dnsb)"' >> ~/.bashrc
```

---

## Log Control

### Global Debugging

```bash
dnsb --debug build test.yml
```

### Module-Level Logging

Use `-l/--log-levels` to specify log levels for each module:

```bash
dnsb build test.yml -l "sub=DEBUG,res=INFO,fs=WARNING"
```

**Module aliases:**
- `sub`: Variable substitution
- `res`: Resource resolution
- `svc`: Service processing
- `bld`: Builder
- `io`/`fs`: File system
- `conf`: Configuration
- `api`: API
- `pre`: Preprocessing

**Wildcards:**
```bash
dnsb build test.yml -l "builder.*=DEBUG"  # All builder submodules
```

### Log File

Save logs to a file:

```bash
dnsb build test.yml -f build.log
```

### Environment Variables

You can also set via environment variables (CLI parameters take precedence):

```bash
export DNSB_LOG_LEVELS="sub=DEBUG,fs=WARNING"
dnsb build test.yml
```

---

## Workflow Examples

### Standard Development Process

```bash
# 1. Build project
dnsb build test.yml -i

# 2. Start services
dnsb run test.yml -d

# 3. Check status
dnsb ps test.yml

# 4. View logs
dnsb logs test.yml -f

# 5. Enter container for debugging
dnsb shell test.yml sld

# 6. Restart services
dnsb restart test.yml sld

# 7. Stop and clean up
dnsb down test.yml -c
```

### Quick Iteration

```bash
# Rebuild and start after modifying configuration
dnsb run test.yml -i --build

# Only restart changed services
dnsb restart test.yml sld tld
```

### Image Management

```bash
# View project images
docker images | grep test-

# Clean project images
dnsb clean test.yml

# Clean all shared images (free disk space)
dnsb clean --all
```

## Reference
- [Configuration File Format](config/index.md)