# Tutorial: from zero to exported chat history

This assumes nothing is installed and nothing has been run before. Ten minutes in total,
most of it spent waiting for the WeChat login.

You end up with a chat history you can browse in a browser, plus readable Moments and
Favorites.

---

## Step 0: the one thing you need to know

**WeChat unlocks every database exactly once — at login.**

So the hook has to be in place before you sign in. Inject afterwards and you only get
the keys for the databases you happen to open (11 of 22 in our measurements, versus 22
of 22 when injecting first).

That is why `all` closes and reopens WeChat and leaves it on the login screen, waiting
for you. `--attach` skips the restart and hooks whatever is already running; use it only
if you know which databases you need.

---

## Step 1: install Rust and build

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # skip if installed
cd sesame
cargo build --release
```

The first build downloads the prebuilt Frida runtime and takes one to three minutes.
Two artifacts matter:

- `target/release/sesame` — the CLI
- `target/release/libsesame_hook.dylib` — the hook library (the CLI looks for it in the
  same directory)

> Keep these two together. Copying only `sesame` elsewhere makes the capture step fail
> with "hook library not found".

> **Every rebuild invalidates the code signature.** Run `sesame sign` (or `sudo sesame
> sign`) after each `cargo build --release`, otherwise the memory checks report
> `kernel returned 5` and key capture cannot work.

## Step 2: check the environment

```bash
./target/release/sesame doctor
```

Expected output looks roughly like:

```
SIP: disabled
process memory access: available
WeChat: 4.1.13  pid 98329
databases: ~/Library/Containers/com.tencent.xinWeChat/Data/.../db_storage (22 files)
```

Three common problems:

| Output | Meaning | Fix |
|---|---|---|
| `SIP: enabled` | System Integrity Protection is on | Disable it (boot to Recovery, `csrutil disable`), or run with `sudo` |
| `process memory access: unavailable (5)` | No debug permission | `sudo sesame sign`, then retry. Re-signing is needed after every rebuild |
| `databases: not found` | WeChat missing, never logged in, or moved | Point at it with `--db-dir` |

## Step 3: run the whole pipeline

```bash
./target/release/sesame all --seconds 180 --out export
```

What happens next:

1. **WeChat quits** (graceful first, force after a timeout)
2. **WeChat relaunches** and stops at the login screen
3. **The hook is injected** — you should see `hooks installed: CCCrypt, CCCryptorCreate, ...`
4. It prints: `hooks are in place. Sign in to WeChat now`
5. **You sign in** — the tool notices the first key and starts its timer
6. It captures for 180 seconds
7. It matches keys, decrypts, and exports chats, Moments and Favorites

Interrupting is safe: the hook stays loaded and the log keeps growing, so you can run
`sesame import <log> --out keys.json` later to collect what was captured.

## Step 4: reading the output

```
export/
├── chat/
│   ├── index.html          <- open in a browser: conversation list on the left
│   ├── index.csv           <- nickname, message count, time range
│   └── text/               <- 401 plain-text files, one per conversation
├── sns/moments.md|.csv
└── favorite/favorites.md|.csv
decrypted/                  <- plain SQLite, open with any tool
keys.json                   <- key and salt per database
```

```bash
open export/chat/index.html
```

Files under `text/` are plain text with a simple shape:

```
# Weekend crew  (group)  108639 messages
# 2025-05-24 21:10:32 ~ 2026-05-20 11:09:37

[2025-05-24 21:10:32] HaFan: [image]
[2025-05-30 06:38:13] Doggie: too late to ask the experts now
```

Images, videos, voice and stickers appear as placeholders only; the media files
themselves are not copied.

## Step 5: running stages separately

To avoid re-capturing every time:

```bash
sesame hook --seconds 180 --out keys.json     # WeChat already running; inject now
sesame decrypt --keys keys.json --out decrypted
sesame export  --dec-root decrypted --out export/chat
sesame sns     --dec-root decrypted --out export/sns
sesame fav     --dec-root decrypted --out export/favorite
```

`decrypt`, `export`, `sns` and `fav` are offline operations. They never touch WeChat
and can be rerun as often as you like.

---

## When something goes wrong

### "no keys captured" or zero databases matched

Most likely causes, in order:

1. **You injected after signing in** — rerun without `--attach`, so the hook is in place first
2. **WeChat is in the background**, or nothing happened after login — open a few chats
   and wait a little
3. **The hook never installed** — check the `hook` output for `hooks installed`.
   If it is missing, run `sesame doctor`; it is usually a permission problem

### `dlopen failed: ...`

The hook library did not load into WeChat. Usually:

- The library is not next to the `sesame` binary — pass it with `--dylib`
- Its signature is broken — delete and rebuild; the tool re-signs a copy into the
  WeChat container on every run

### WeChat crashed / will not start

Just open it again. If a **Safe Mode** dialog appears, click Continue and it starts
normally.

A crash means something on the hook path went wrong; keep the full output of
`sesame hook` for diagnosis.

### `quick_check` fails on `*_fts.db`

Expected. Full-text index shadow tables are not part of the consistency check and body
text export is unaffected. If the **four main databases** (`message_0/1`, `contact`,
`session`) fail, the key is wrong — capture again.

### "page N does not decrypt, page parameters may be wrong"

That database uses a layout different from the others. The tool already tries four page
sizes and five reserve sizes. If all fail, keep a copy of that database — it is a new
case worth investigating.

---

## Another machine, another account

`sesame` is a single binary. Copy `sesame` and `libsesame_hook.dylib` together and the
workflow is identical: `doctor`, then `all`.

The database directory is discovered from the signed-in account
(`xwechat_files/wxid_*/db_storage`), so switching accounts needs no flags. If several
accounts exist and the wrong one is picked, pass `--db-dir`.

---

## Privacy

After a run you will have these **plaintext** files: `keys.json`, `decrypted/`, `export/`.

- Keep them off iCloud, Dropbox, or any sync drive
- Do not commit them (the repository's `.gitignore` already excludes them)
- Delete them when done — the original databases were never modified
