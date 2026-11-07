# CLI reference

Every command accepts `--db-dir` to override the auto-detected database directory.

```
sesame <command> [options]
```

## doctor

Environment check: SIP status, process memory access, WeChat version, database location.
**Run this first whenever something is off.**

```bash
sesame doctor
```

No options.

## sign

Re-signs the `sesame` binary with `com.apple.security.cs.debugger` and `get-task-allow`.
Reading another process's memory without root requires it. Re-sign after every rebuild.

```bash
sesame sign
```

No options.

## scan

Read-only scan of WeChat's memory for database keys. On 4.1.x this usually finds nothing
(keys are not resident); it is kept for older versions and diagnostics.

```bash
sesame scan [--pid N] [--out keys.json] [--stride 4] [--all] [--include-readonly] [--chunk-mb 64]
```

| Option | Default | Meaning |
|---|---|---|
| `--pid` | auto | WeChat process id |
| `--out` | `keys.json` | key output file |
| `--stride` | `4` | scan step in bytes; 8 is faster but may miss |
| `--all` | off | scan every database (default: messages, contacts, sessions only) |
| `--include-readonly` | off | also scan read-only regions; slow |
| `--chunk-mb` | `64` | read size per chunk |

## hook

Injects the hook library and captures keys at runtime.

```bash
sesame hook [--pid N] [--seconds 120] [--out keys.json] [--dylib path] [--loader frida|builtin]
```

| Option | Default | Meaning |
|---|---|---|
| `--seconds` | `120` | capture window after successful injection |
| `--out` | `keys.json` | key output file |
| `--dylib` | `libsesame_hook.dylib` next to the binary | hook library path |
| `--loader` | `frida` | `builtin` is a hand-written Mach injector; **it crashes WeChat**, debugging only |

## inject

Injects only: no capture, no matching. For debugging.

```bash
sesame inject --pid 1234 [dylib path]
```

## import

Takes keys from a hook log (JSONL) and matches them to databases. The log keeps growing
after the hook exits, so this can be rerun at any time.

```bash
sesame import <log path> [--out keys.json] [--db-dir dir]
```

Matching is cryptographic: every key is tested against every database's first page,
survivors are confirmed with `quick_check`.

## decrypt

Decrypts databases into a new directory. **The originals are never modified.**

```bash
sesame decrypt [--keys keys.json] [--out decrypted] [--db-dir dir]
```

Page parameters are auto-detected, and committed pages from `-wal` files are merged.

## export

Exports chat history, including direct chats, groups and official accounts.

```bash
sesame export [--dec-root decrypted] [--out export] [--min-messages 1]
```

| Option | Default | Meaning |
|---|---|---|
| `--dec-root` | `decrypted` | decrypted database directory |
| `--out` | `export` | output directory |
| `--min-messages` | `1` | skip conversations with fewer messages |

## sns

Exports Moments: text, media count, location, likes and comments.

```bash
sesame sns [--dec-root decrypted] [--out export_sns]
```

Writes `moments.md` and `moments.csv`.

## fav

Exports Favorites in reverse chronological order.

```bash
sesame fav [--dec-root decrypted] [--out export_fav]
```

Writes `favorites.md` and `favorites.csv`.

## all

Everything: capture, match, decrypt, all three exports.

```bash
sesame all [--attach] [--seconds 180] [--keys keys.json] [--dec-root decrypted] [--out export]
```

| Option | Default | Meaning |
|---|---|---|
| `--attach` | off | inject into the running WeChat instead of restarting it. Attach mode only sees the databases you open yourself |
| `--seconds` | `180` | capture window after login |

## Exit codes

- `0` success
- non-zero if a stage failed; see stderr. Inside `all`, a failing Moments or Favorites
  export is reported and skipped rather than aborting the run.
