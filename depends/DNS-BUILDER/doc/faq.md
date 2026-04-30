# FAQ

This page summarizes common errors and solutions encountered when using DNSB, organized by error type and scenario. It is recommended to use `--debug` to view detailed logs for troubleshooting.

## General Troubleshooting Tips

- Enable debug logging: Append `--debug` when running the CLI, or check the console output when running the API.
- Minimize configuration for reproduction: First remove complex includes/templates/DSL, keeping only core fields, then gradually add them back.
- Paths and mounts: Read [File Paths and FS](rule/paths-and-fs.md) to confirm the behavior of `resource:/`, relative/absolute paths.

### Logging and Troubleshooting

- Global level: After enabling `--debug`, the base level is `DEBUG`; without it, the level is `INFO`.
- Module-level fine-tuning: `-l/--log-levels` supports setting the level for specific modules individually, overriding the global setting. Example:

  ```shell
  dnsb config.yml --debug -l "res=INFO"    # using alias
  dnsb config.yml -l "builder.*=DEBUG"                 # top-level wildcard, equivalent to dnsbuilder.builder
  setx DNSB_LOG_LEVELS "fs=WARNING,api=DEBUG"        # environment variable (CLI parameter takes priority)
  dnsb config.yml
  ```
- Aliases and auto-prefix:

  - Aliases include `sub, res, svc, bld, io, fs, conf, api, pre`, which expand to full module names.
  - `builder.*` represents the base logger (remove `.*`); names not starting with `dnsbuilder.` but belonging to known top-level module names (e.g., `builder`, `io`, `api`, etc.) will automatically be prefixed.
- Typical scenario:

  - Set substitution process to DEBUG, ignore everything else: `-l "sub=DEBUG"`

## Configuration Loading and Validation

- ConfigFileMissingError
  - Symptom: Prompt indicating the configuration file cannot be found
  - Common cause: The path to `config.yml` is incorrect; in API mode, the project directory was accidentally deleted or missing `dnsbuilder.yml`
  - Solution: Confirm the path is correct; in API mode, check `.dnsb_cache/workspace/<project_name>/dnsbuilder.yml` for the configuration
- ConfigParsingError
  - Symptom: YAML syntax error (indentation/list/string, etc.)
  - Common cause: Inconsistent list indentation; missing spaces in key-value pairs; incorrect multi-line text indentation
  - Solution: Use a YAML validation tool to check; standardize the example style to "top-level dictionary", avoid mixing multiple structures
- ConfigValidationError
  - Symptom: Structural validation failed (Pydantic error)
  - Common causes and fixes:
    - Both `image` and `ref` are missing in `builds` → provide at least one of them
    - Using `std:` template without providing `image` → `image` must be provided (it determines the software type)
    - Using `ref` in `images` while also providing `software/version/from` → these are mutually exclusive, use only one
    - Image name contains a colon or is duplicated → remove the colon and ensure uniqueness
    - `inet` is not a valid private IPv4 network segment → use a valid segment such as `10.88.0.0/24`

## Definitions and References

- ReferenceNotFoundError
  - Symptom: The image/service pointed to by `ref` does not exist
  - Common cause: Case inconsistency; referencing a name that has not yet been defined; include merge/override causing key loss
  - Solution: Confirm the referenced item exists and the spelling is consistent; adjust the include order or key override strategy
- CircularDependencyError
  - Symptom: Circular reference between images or services
  - Common cause: A references B, and B references A; chain of `ref` forming a closed loop
  - Solution: Break the loop; eliminate mutual references, use explicit templates or independent definitions
- ImageDefinitionError / BuildDefinitionError
  - Symptom: Image or service definition is invalid (conflicting keys, unsupported template, etc.)
  - Common cause: Image declares both `software/version/from` and `ref`; service `ref` points to an unknown template; `std:` template does not match the `image` type
  - Solution: Follow the mutual exclusivity and matching rules; refer to [Standard Service Templates](rule/build-templates.md) to ensure the combination is valid
- NetworkDefinitionError (may occur in fixed address scenarios)
  - Symptom: Static address or network segment is invalid
  - Common cause: `address` does not belong to the project's `inet` subnet; format does not conform to IPv4
  - Solution: Ensure `address` is within the `inet` range and is valid

## Build Phase

- VolumeError
  - Symptom: Volume processing failed (source path does not exist or cannot be copied)
  - Common cause: Mount source not found; absolute path copy rules not understood; missing actual values for `${required}` placeholders
  - Solution: Check that the path exists; follow the rule "absolute paths are not copied, relative paths are copied to `service_name/contents`"; ensure placeholders have values
- BehaviorError
  - Symptom: Behavior DSL parsing or generation failed (e.g., Zone definition abnormality)
  - Common cause: DSL syntax does not conform to Behavior DSL; variable substitution failed; template does not support this behavior
  - Solution: Refer to the [Behavior DSL](rule/behavior-dsl.md) specification; simplify the behavior script to locate the issue; verify variables and template support scope
- UnsupportedFeatureError
  - Symptom: Requested a feature that has not yet been implemented or an unsupported combination
  - Solution: Adjust to a supported configuration; pay attention to available features in release notes and documentation

## Paths and File System

- InvalidPathError / ProtocolError
  - Symptom: Path or protocol is not supported (e.g., incorrect `resource:/`/custom protocol)
  - Solution: Only use supported protocols; confirm that the `resource:/` path exists in built-in resources
- DNSBPathNotFoundError / DNSBPathExistsError / DNSBNotAFileError / DNSBNotADirectoryError
  - Symptom: File/directory does not exist, already exists, type mismatch, etc.
  - Solution: Verify the target path; avoid performing "write file" operations on directories or vice versa; if necessary, adjust `parents=True` to create directories
- ReadOnlyError
  - Symptom: Attempting to write on a read-only file system
  - Solution: Confirm the current FS mode (only disk file system and memory file system are writable; other protocol file systems are read-only), use a writable FS in scenarios that require writing

## API Usage and Status Codes

- 404: `ConfigFileMissingError` or `ReferenceNotFoundError`
  - Description: Project or configuration missing; or referenced object does not exist.
  - Solution: Create the project and place `dnsbuilder.yml`; correct the reference name.
- 422: `ConfigValidationError`
  - Description: Structural validation failed.
  - Solution: Fix required fields and constraints one by one according to the "Configuration Validation" section.

## Port Conflicts and Running

- Backend service: `dnsb --ui` defaults to `http://localhost:8000`.
- Documentation preview: `mkdocs serve -a 127.0.0.1:8001`; use a different port from the backend to avoid conflicts.
- Conflict handling: If 8000/8001 is occupied, close the occupying process or change the preview port.

## Common Scenario Quick Reference

- "std: prefix error": `image` not provided, or `image` software type does not match the template role
- "Circular reference": Simplify and break the `ref` chain; avoid A↔B mutual reference
- "Mount failure": Check that the source path exists; understand absolute/relative path copy and mount rules; confirm `resource:/` resources are available
- "DSL generation failed": Reduce behaviors; verify syntax and template support; check parsing steps in debug logs