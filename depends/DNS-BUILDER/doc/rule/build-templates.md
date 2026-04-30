# Standard Service Templates

Standard service templates are used to quickly declare service configurations for common roles, resolved through the combination of `ref: "std:<role>"` and the service's `image` software type

## Resolution Rules

- When `ref` is written as `std:<role>`, the parser reads the service's `image`, obtains its software type (such as `bind`, `unbound`), and interprets `std:<role>` as `<software>:<role>`
- If `image` is not set or the software type cannot be recognized, an error will be thrown
- You can also write `<software>:<role>` directly (such as `bind:auth`, `unbound:recursor`), skipping the `std:` combination resolution

## Available Templates

Built-in templates are located in the resource path `resource:/builder/templates`, currently including:

- `bind`

  - `recursor`: Recursive resolver, mounts `bind_recursor_base.conf` etc.
  - `auth`: Authoritative server, mounts `bind_auth_base.conf`
  - `forwarder`: Forwarder, mounts `bind_forwarder_base.conf`
- `unbound`

  - `recursor`: Recursive resolver, mounts `unbound_recursor_base.conf`
  - `forwarder`: Forwarder, mounts `unbound_forwarder_base.conf`

## Usage Examples

```yaml
builds:
  recursor:
    image: "bind"
    ref: "std:recursor"
  root:
    image: "bind"
    ref: "bind:auth"  # Explicit form
```

## Variable Substitution and Mounting

Templates may contain placeholders (such as `${project.inet}`, `${origin}`, `${required}`), which are resolved by the variable substitution engine during the build process. See [Behavior DSL](behavior-dsl.md) and [Built-in Variables](builtins-and-placeholders.md) chapters

## Further Reading

- [Behavior DSL](behavior-dsl.md)
- [Built-in Variables](builtins-and-placeholders.md)