# Deprecated Features Documentation

This directory contains documentation for features that are outdated, scheduled for removal, or no longer recommended for use. These features are still available in the code (to maintain backward compatibility), but should not be used in new projects.

## Included Documents

- [Comprehension Syntax](comprehension.md) **Deprecated**
  - Used for batch generating `images` or `builds` entries
  - Recommended alternative: Use [Auto Automation Scripts](../config/auto.md) `setup` phase to achieve the same functionality
  - Removal plan: Will be removed in future versions

## Migration Guide

If you are using these deprecated features, here are the steps to migrate to the new recommended approach:

### Comprehension Syntax -> Auto Setup

**Old way (comprehension):**
```yaml
builds:
  - name: "service-{{ value }}"
    for_each:
      range: [1, 3]
    template:
      image: "bind"
      ref: "std:auth"
```

**New way (Auto):**
```yaml
auto:
  setup: |
    for i in range(1, 4):
      config.setdefault('builds', {})[f'service-{i}'] = {
        'image': 'bind',
        'ref': 'std:auth'
      }

builds: {}
```

## Related Documentation

- [Auto Automation Scripts - Migration Guide](../config/auto.md)
- [Configuration Overview](../config/index.md)
- [Configuration Processing Pipeline](../config/processing-pipeline.md)