# DNSB

DNSBuilder is a tool for constructing and simulating DNS environments, including:

- **CLI**: Full functionality, can directly generate build artifacts from configuration, supports container management
- **API**: Based on FastAPI, provides project, build, resource interfaces; current UI is still under construction
- **DNSSEC**: Automatic signing and key management, transparent integration
- **Builder Service Mode**: Smart image reuse, avoids concurrent conflicts

This documentation helps you quickly understand, install, use, and extend DNSB.

## Port & Running Notes

- Backend API:
  - Running `dnsb ui` starts the backend service, default address is `http://localhost:8000`
  - API usage examples see [API Usage](api/index.md) and OpenAPI
- Documentation preview: Local documentation preview defaults to `http://localhost:8001` (example command: `mkdocs serve -a 127.0.0.1:8001`)
- Port conflicts: If `8000/8001` are occupied, close the occupying process or temporarily adjust the preview port to avoid conflicts

## Quick Path

- **CLI Commands**: See [CLI Command Reference](cli.md) for all available commands and options
- **File Paths & Mounting**: It's recommended to first read the resource path and file system documentation to understand `resource:/`, relative/absolute path copy and mount behavior. See [File Paths & FS](rule/paths-and-fs.md)
- **Getting Started**: After [installing as required](root/install.md), follow [Getting Started](root/getting-started.md) and run `dnsb build config.yml` using the example
- **Container Management**: Use `dnsb run`, `dnsb up`, `dnsb down` and other commands to manage container lifecycle
- **DNSSEC Support**: See [DNSSEC Documentation](dnssec.md) for automatic signing features
- **Configuration Generation**: Learn about [Configuration Generation Mechanism](config-generation.md), master Section, Includer, and configuration file path syntax
- If you encounter problems, check [Configuration Reference](config/index.md) and [FAQ](faq.md), focusing on common pitfalls like circular references, template usage, and path mounting
- When you need to execute custom logic during configuration generation or modification phases, use [Auto Automation Scripts](config/auto.md)
- To understand the full configuration processing flow, refer to [Configuration Processing Pipeline](config/processing-pipeline.md)