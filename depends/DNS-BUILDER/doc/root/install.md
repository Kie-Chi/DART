# Installation & Running

## Environment Preparation

- Docker & Compose: A working Docker environment must be installed (on Windows, Docker Desktop + WSL2 is recommended). Verify: `docker --version` and `docker compose version` both produce normal output.

## Installation

```shell
pip install .
```

## Running (CLI)

```shell
dnsb COMMAND CONFIG_FILE [OPTIONS]
```

### Common Commands

- `build`: Build project configuration
- `run`: Build and start containers
- `up`: Start an already-built project
- `down`: Stop and clean up containers
- `shell`: Enter container shell
- `logs`: View container logs
- `ps`: List container status
- `clean`: Clean images

For detailed command descriptions, see [CLI Command Reference](../cli.md)

### Common Options

- `--debug`: DEBUG mode, output more detailed logs
- `-h`: Get CLI parameter help
- `-g/--graph GRAPH_PATH`: Generate service topology for the build process, save to `GRAPH_PATH`
- `--vfs`: In-memory build, no real disk space used
- `-l/--log-levels`: Module-level log control
- `-f/--log-file`: Save log file
- `-i/--incremental`: Enable incremental build cache
- `-w/--workdir WORKDIR`: Specify working directory
  - Defaults to the current directory where the command is run
  - `@config` represents the directory containing the configuration file
  - Also supports relative paths (relative to current directory) or absolute paths

#### Log Examples

```shell
# Global debug + specify submodule levels (aliases: sub, res, svc, bld, io, fs, conf, api, pre)
dnsb demo.yml --debug -l "res=INFO"

# Apply to top-level builder (auto-completed to dnsbuilder.builder)
dnsb demo.yml -l "builder.*=DEBUG"

# Use environment variables (CLI parameters take priority)
setx DNSB_LOG_LEVELS "sub=DEBUG,fs=WARNING"
dnsb demo.yml

```


## Running (GUI)

```shell
dnsb --ui
```

- Currently only API is available