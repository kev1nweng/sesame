# Engineering notes (WeChat 4.1.13 / macOS 27 / Apple Silicon)

Why the code looks the way it does, including the approaches that failed. Read this
before changing anything non-trivial.

## Encryption parameters

SQLCipher 4, AES-256-CBC, 4096-byte pages, 80 bytes reserved per page
(16-byte IV + 64-byte HMAC-SHA512).

The page layout we measured differs from what is commonly published. It is verified with
`PRAGMA quick_check`:

```
first 16 bytes of file = salt
page 1: salt(16) + AES(plaintext[16:4016]) + IV(16) + HMAC(64) = 4096
page n:           AES(plaintext[0:4016])  + IV(16) + HMAC(64) = 4096
```

The IV sits at `[4016, 4032)`, so every page can be decrypted independently — no
serialisation, no dependency on previous pages.

## On 4.1.x the keys are never resident in memory

- Scanned 1.5 GB of writable memory and 400 million candidate offsets: zero hits
- The matcher was validated against a known key (it recovers the header
  `1000020250402020`)
- Including read-only regions still gave zero hits
- Conclusion: the key is materialised only for the duration of a crypto call and wiped
  afterwards. Capturing it requires intercepting the call site.

This is why `scan` is mostly decorative on 4.1.x.

## WeChat does not go through the GOT, and not through an interceptable `dlsym`

- Rewriting the GOT with fishhook: all 35 images patched (including the container
  plugin), process stayed healthy, zero hits after clicking through chats
- Adding a `dlsym` interceptor returning our own functions: still zero hits
- Conclusion: it calls straight into the shared cache. The GOT route is a dead end.

## Inline hooking is blocked by OS policy

- Anonymous pages cannot be made `PROT_EXEC` (macOS 27 JIT policy)
- `mprotect` and `VM_PROT_COPY` on shared-cache pages both fail; forcing it gives a
  bus error
- Conclusion: hand-rolled inline hooks are not viable. `frida-gum` provides its own
  trampolines and executable memory handling, which works.

## Three attempts at a loader

| Approach | Result |
|---|---|
| Hand-written Mach injector | works on normal processes, **three SIGSEGV crashes in WeChat** |
| Frida `inject_library_file` | fails: frida-helper needs `/usr/lib/libiconv.2.dylib`, absent on this macOS |
| Frida attach + script `dlopen` | works; WeChat stays healthy and the hook installs |

Four reasons the hand-written injector crashed WeChat (all encountered):

1. Mach threads must be registered through `pthread_create_from_mach_thread`
2. The carrier thread must wait for the constructor to finish before `thread_terminate`
3. Reverting fishhook pages to read-only breaks dyld lazy binding
4. **Allocating inside the hook path (`format!`, `Mutex`) causes SIGSEGV** — the
   subtlest one

Reason 4 was found last: the hook runs near the host's malloc critical sections, and
allocating there eventually corrupts state. The current hook does exactly three things:
read arguments, hex-encode on the stack, one `write(fd, ...)`. It never touches the heap.

## Inject before login, not after

Measured:

| Timing | Databases captured |
|---|---|
| Inject after login, open 5 chats | 11 / 22 |
| Inject before login, sign in normally | **22 / 22** |

WeChat decrypts every database once at login. That is the only moment where all keys
exist. Hence `sesame all --restart`.

## Measured scale

- 22 databases, 19–22 pass `quick_check` (the `*_fts.db` ones are flaky; shadow tables
  are not part of the consistency check)
- Chats: 401 conversations / 615,106 messages (including 97 official-account threads)
- Moments: 14,636 posts / 3,862 likes / 523 comments
- Favorites: 128 items

## `local_type` is a packed integer

`local_type` is not a small enum; it is `(subtype << 32) | base type`:

| local_type | Meaning |
|---|---|
| 1 | text |
| 3 | image |
| 47 | animated sticker |
| 244813135921 | 49+57 quoted message |
| 17179869233 | 49+4 link |
| 8589934592049 | 49+2000 transfer |
| 10000 | system message |

Unknown types now render as `[unknown type N]` instead of dumping raw XML into the
conversation text.
