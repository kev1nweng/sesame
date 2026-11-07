# sesame

sesame pulls the SQLCipher keys out of a running WeChat on macOS, decrypts its
databases, and writes them somewhere you can read them.

What you end up with is plain SQLite you can open with any tool, plus text exports:
every conversation (direct chats, groups, official accounts), Moments with likes and
comments, Favorites, and the decrypted contact database behind all those names. It's
one Rust binary, and it never writes to WeChat or the original databases.

A candidate key only counts if it decrypts a database page into a valid SQLite header,
and the page layout is detected at runtime instead of being hardcoded. WeChat can
rearrange its tables or ship a new build; decryption still works. What a new release can
affect is how a few message types render, and [Surviving version changes](#surviving-version-changes)
is honest about that.

```
WeChat process ──hook──> key log ──verify──> keys.json
                                             │
original *.db ─────────────decrypt───────────┘──> text / CSV / HTML
```

## Why it works this way

A hook on WeChat's crypto calls writes key material to a log. Each candidate key is
then used to decrypt page 1 of every database. If the result is not a valid SQLite
header, the key is wrong; nothing about WeChat's table layout can confuse that test.

The hook allocates nothing, takes no locks, and does not format strings. It runs on a
hot path shared with the host's allocator, and allocating there is what crashed WeChat
in earlier builds.

WeChat unlocks every database exactly once, at login. Injecting before you sign in
captures all of them. Injecting afterwards only catches the databases you open by hand.

## Requirements

- macOS (Apple Silicon or Intel), WeChat 4.x
- Ability to debug the target process. `sesame doctor` reports SIP status and whether
  `task_for_pid` works
- Network access on first build (downloads the prebuilt Frida runtime)

## Quick start

```bash
cargo build --release

./target/release/sesame doctor
./target/release/sesame all --seconds 180 --out export
```

By default `all` quits WeChat, relaunches it, injects the hook while the login screen is
up, waits for you to sign in, captures for 180 seconds, matches keys, decrypts, and
exports.

You have to click through the login yourself, because WeChat requires it.

If WeChat is already running and you would rather not restart:

```bash
./target/release/sesame all --seconds 180 --out export
```

This usually only yields the keys for databases you have open.

## Documentation

| Document | Contents |
|---|---|
| [Tutorial](docs/tutorial.md) | Full walkthrough from zero, with expected output and a troubleshooting table |
| [CLI reference](docs/cli.md) | Every subcommand, flag and default |
| [Engineering notes](docs/notes.md) | Reverse-engineering findings, dead ends, crash post-mortems |

## Commands

| Command | Purpose |
|---|---|
| `doctor` | Environment check: SIP, process memory access, WeChat version, database location |
| `sign` | Re-sign the binary with debug entitlements (needed to read memory without root) |
| `scan` | Read-only memory scan for keys (unlikely to hit on 4.1.x, see notes) |
| `hook` | Inject the hook library and capture keys at runtime |
| `inject` | Inject only, for debugging |
| `import` | Import keys from a hook log and match them to databases |
| `decrypt` | Decrypt databases using `keys.json` |
| `export` | Export chat history (including official accounts) |
| `sns` | Export Moments: text, media count, location, likes, comments |
| `fav` | Export Favorites: text, images, links, files, chat records, music |
| `all` | Everything: capture, decrypt, all three exports |

## Output

```
keys.json              key and salt per database
decrypted/             plain SQLite, open with any tool
export/
  chat/index.html      browsable chat overview
  chat/text/*.txt      one file per conversation
  chat/index.csv       conversation list
  sns/moments.md|.csv
  favorite/favorites.md|.csv
```

## How it works

1. Injection: attach with `frida-core` and run a small script that calls `dlopen` on
   the hook library. Frida's `inject_library_file` would be the obvious API, but it
   goes through frida-helper, which fails on recent macOS because
   `/usr/lib/libiconv.2.dylib` no longer exists on disk.
2. Hooking: `frida-gum` installs listeners on `CCCrypt`, `CCCryptorCreate` and
   `CCCryptorCreateWithMode`, writing key and IV pairs to a JSONL file inside the
   WeChat container.
3. Matching: each candidate key is tested against each database's first page, and
   survivors are confirmed with `PRAGMA quick_check`.
4. Decryption: SQLCipher 4 pages (4096 bytes, 80 bytes reserved for a 16-byte IV and a
   64-byte HMAC). Page parameters are detected, and committed pages from `-wal` files
   are merged in.

## Surviving version changes

From most to least stable:

| Layer | Depends on | What breaks it |
|---|---|---|
| Key verification | pure cryptography | essentially nothing |
| Page decryption | SQLCipher standard layout | WeChat changing page parameters (auto-detected) |
| Hook points | Apple's CommonCrypto | WeChat bundling its own crypto library |
| Injection | `task_for_pid` | OS tightening debug permissions |
| Export | WeChat's own tables | new message types (shown as `[unknown type N]`, rest unaffected) |

WeChat's schema is additive in practice: new columns, tables and database files are
absorbed without changes here. The real variables across versions are the crypto implementation
and OS permission policy, not the schema.

## Known limitations

- Full-text index databases (`*_fts.db`) may fail `quick_check`; shadow tables are not
  part of the consistency check, and body text export is unaffected.
- Images, videos and voice messages are exported as placeholders. The media files
  themselves live elsewhere in WeChat's container and are not copied.
- On 4.1.x keys never stay resident in memory, so `scan` will usually find nothing.
  It is kept for older versions and for diagnostics.
- macOS only.

## Privacy

`keys.json`, `decrypted/` and `export/` contain plaintext private data. Keep them off
sync drives and out of git (`.gitignore` already excludes them). Use this only on data
you own.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
