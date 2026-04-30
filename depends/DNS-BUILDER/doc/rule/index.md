# Overview

This page summarizes DNSBuilder's syntax and rules, helping you understand when writing configurations

- How to generate configurations through automation scripts
- How to merge and override
- How to reference templates
- How to resolve paths

## Topic Overview

- Automation scripts: Use Python scripts to automate the setup (initialization), modify (modification), and restrict (validation) phases of configuration
- Merge and override: Deep merge model, recursive dictionaries, deduplicated list appending, `KEY=VALUE` list normalization merging
- Standard service templates: Reference standard roles with `std:<role>`, combined with the image's software type to resolve as `<software>:<role>`
- Behavior DSL: Declare service behavior scripts, generating concrete configurations for BIND/Unbound etc.
- RuleSet: Version rule matching, supporting version validation, base image selection, and dependency management
- Built-in variables and placeholders: Support variables like `${origin}`, participating in substitution during template rendering
- File paths and FS: Protocol and URI resolution, cross-filesystem copy rules, path usage for `include/files/volumes`

## When to Use These Rules

- Use automation scripts when you need to dynamically generate or modify configurations
- Rely on merge and override rules when you need to merge multiple configurations or stack templates/mixins
- Use standard service templates when you need to quickly set up common roles (recursor, authoritative, forwarder)
- Pay attention to path and FS rules when you need to pull configuration files from resources/Git/servers and copy them into containers
- Reference [Configuration Processing Pipeline](../config/processing-pipeline.md) when you need to understand the complete flow from configuration loading to output
- Reference [Configuration Generation Mechanism](../config-generation.md) when you need to understand the configuration fragment assembly mechanism

## Further Reading

- [Configuration Processing Pipeline](../config/processing-pipeline.md)
- [Automation Scripts (Auto)](../config/auto.md)
- [Merge and Override Rules](merge-and-override.md)
- [Standard Service Templates](build-templates.md)
- [Behavior DSL](behavior-dsl.md)
- [RuleSet](ruleset.md)
- [Built-in Variables and Placeholders](builtins-and-placeholders.md)
- [File Paths and FS](paths-and-fs.md)
- [Deprecated: Comprehension Syntax](../old/comprehension.md)