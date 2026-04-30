# Overview

This page provides the simplest path for writing DNSBuilder configuration: build a project in the order of "top-level -> images -> services", with details expanded on the corresponding pages.

## Structure & Responsibilities

- Top-level configuration: project name, network segment, collection of images and services (entry point)
- Image configuration: internal images (determine software type and build environment) / external images (community or user-defined images)
- Service configuration: specific container runtime parameters, supporting standard templates and behavior scripts

## Minimal Working Example

```yaml
name: demo
inet: 10.88.0.0/24
builds: {}
```

## Core Constraints (Quick View)

- Images & Services: Must use dictionary format; list expansion is no longer supported
- Images: `ref` and `software/version/from` are mutually exclusive; image names cannot be duplicated and cannot contain colons
- Services: Require `image` or `ref`; when using `std:` templates, `image` must be provided
- References: Peer `ref` supports chain inheritance; circular or unknown references will cause errors
- Include: Supports relative, absolute, and `resource:/` paths; integrates configuration using deep merge strategy
- Auto: Supports executing Python scripts at three stages (setup, modify, restrict) to dynamically manage configuration

## Configuration File Path Syntax

When mounting configuration files in `volumes`, you can use special syntax to specify the target section and parameters:

```yaml
volumes:
  # Suffix format: .options indicates the options section
  - ./options.conf:/etc/named.conf.options

  # Fragment format: # specifies the section
  - ./custom.conf:/etc/named.conf#server

  # With parameters format: ?name=value specifies template parameters
  - ./zone.conf:/etc/zones.conf?name=example.com#zone
```

See [Configuration Generation Mechanism](../config-generation.md) for details.

## Further Reading

- [Configuration Processing Pipeline](processing-pipeline.md)
- [Configuration Generation Mechanism](../config-generation.md) — Section, Includer, configuration fragment details
- [Auto Automation Scripts](auto.md)
- [Top-level Configuration](top-level.md)
- [Image Configuration](images.md)
- [Service Configuration](builds.md)
- [Syntax & Rules Overview](../rule/index.md)