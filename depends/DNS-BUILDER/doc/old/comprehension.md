# Comprehension Syntax (Deprecated)

**This feature is outdated and scheduled for removal. It is not recommended for use in new projects.**

Please use the latest configuration format (dictionary format) to directly define `images` and `builds`. If you need to generate many similar configurations, it is recommended to use the `auto.setup` automation feature or external configuration generation tools.

---

## Migration

If you previously used comprehension syntax to generate multiple similar services, you can now switch to `auto.setup`:

**Old way (comprehension, deprecated):**
```yaml
builds:
  - name: "sld-{{ value }}"
    for_each:
      range: [1, 3]
    template:
      image: "bind"
      ref: "std:auth"
      behavior: |
        example.com master www A 1.2.3.{{ value }}
```

**New way (auto.setup):**
```yaml
auto:
  setup: |
    for i in range(1, 4):
      name = f"sld-{i}"
      config.setdefault('builds', {})[name] = {
        'image': 'bind',
        'ref': 'std:auth',
        'behavior': f'example.com master www A 1.2.3.{i}'
      }

builds: {}
```


Used for batch generating `images` or `builds` entries, combining `name` templates, iterators, and configuration templates through comprehension blocks in list items to achieve concise declaration of repetitive structures.

## Syntax Structure

- Location: Used in **list items** of `images:` or `builds:`, **not supported in dictionary items**
- Required keys: `name`, `for_each`, `template`
- Parsing order: Read and expanded during preprocessing phase, then enters validation and parsing

```yaml
# Example with builds
builds:
  - name: "sld-{{ value }}"
    for_each:
      range: [1, 3]
    template:
      image: "bind"
      ref: "std:auth"
      behavior: |
        example.com master www A 1.2.3.{{ value }}
        example.com master mail A 1.2.3.{{ value + 1 }}
```

## for_each Supported Iterators

- List: `for_each: [a, b, c]`, sequentially sets `value` to list elements, `i` as index
- Range: `for_each: { range: N }` or `for_each: { range: [start, stop] }` or `for_each: { range: [start, stop, step] }`

## Context Variables

- `value`: Current iteration value; used to render `name` and string fields within `template`
- `i`: Current iteration index (starting from 0)

## Rendering Scope

- String fields will be rendered as Jinja2 templates; objects and arrays will recursively render their string values
- Conflict detection: If the rendered `name` duplicates an existing entry, an error will be reported

## Using in images (Not Recommended)

```yaml
images:
  - name: "bind-{{ i }}"
    for_each: 3
    template:
      ref: "bind:9.18.0"
```

## Errors & Validation

- Missing any required key (`name`, `for_each`, `template`) will report an error
- `for_each.range` can only be an integer or integer list; otherwise an error is reported
- List items that are not comprehension blocks, explicit `name`, or single-key dictionaries will report an error



## Further Reading

- [Service Configuration](../config/builds.md)
- [Internal Image Configuration](../config/images.md)
- [Merge & Override Rules](../rule/merge-and-override.md)
- [File Paths & FS](../rule/paths-and-fs.md)
- [Auto Automation Scripts](../config/auto.md)