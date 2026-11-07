// SPDX-License-Identifier: AGPL-3.0-or-later
//! Hook library injected into WeChat, built on frida-gum's Interceptor.
//!
//! Why gum: CommonCrypto lives in the dyld shared cache and ordinary processes cannot
//! patch its code pages. gum handles trampolines and executable memory, so a version
//!
//! change usually only means swapping hook points.

use std::ffi::CString;
use std::io::Write;
use std::os::raw::{c_char, c_void};
use std::sync::atomic::{AtomicI32, Ordering};

use frida_gum::interceptor::{Interceptor, InvocationContext, InvocationListener};
use frida_gum::{Gum, NativePointer};

static LOG_FD: AtomicI32 = AtomicI32::new(-1);

fn out_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    std::path::PathBuf::from(home).join("sesame-keys.jsonl")
}

/// Init-time: open the log file so the hook path only needs an fd.
fn open_log() {
    let path = out_path();
    let Ok(c) = CString::new(path.as_os_str().as_encoded_bytes()) else {
        return;
    };
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
            0o644,
        )
    };
    LOG_FD.store(fd, Ordering::Relaxed);
}

fn log(line: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(out_path())
    {
        let _ = f.write_all(line.as_bytes());
        let _ = f.flush();
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Hex encoding on the stack; allocation-free.
unsafe fn put_hex(buf: &mut [u8], mut n: usize, src: *const u8, len: usize) -> usize {
    for i in 0..len {
        let b = *src.add(i);
        buf[n] = HEX[(b >> 4) as usize];
        buf[n + 1] = HEX[(b & 0xf) as usize];
        n += 2;
    }
    n
}

unsafe fn put_str(buf: &mut [u8], mut n: usize, s: &[u8]) -> usize {
    buf[n..n + s.len()].copy_from_slice(s);
    n += s.len();
    n
}

/// The hook only does: read args, build bytes on the stack, one write().
/// No allocation, no locks, no formatting, so it cannot die inside malloc's critical section.
unsafe fn record(kind: &[u8], key: *const u8, key_len: usize, iv: *const u8, op: u32) {
    if key.is_null() || key_len != 32 {
        return;
    }
    let fd = LOG_FD.load(Ordering::Relaxed);
    if fd < 0 {
        return;
    }
    let mut buf = [0u8; 256];
    let mut n = 0usize;
    n = put_str(&mut buf, n, b"{\"kind\":\"");
    n = put_str(&mut buf, n, kind);
    n = put_str(&mut buf, n, b"\",\"key\":\"");
    n = put_hex(&mut buf, n, key, 32);
    n = put_str(&mut buf, n, b"\",\"iv\":\"");
    if !iv.is_null() {
        n = put_hex(&mut buf, n, iv, 16);
    }
    n = put_str(&mut buf, n, b"\",\"op\":");
    if op >= 10 {
        buf[n] = b'0' + (op / 10) as u8;
        buf[n + 1] = b'0' + (op % 10) as u8;
        n += 2;
    } else {
        buf[n] = b'0' + op as u8;
        n += 1;
    }
    n = put_str(&mut buf, n, b"}\n");
    libc::write(fd, buf.as_ptr() as *const c_void, n);
}

/// Password derivation: one line per distinct salt.
unsafe fn record_pbkdf(
    kind: &[u8],
    password: *const c_char,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    rounds: u32,
    derived: *const u8,
    derived_len: usize,
) {
    let fd = LOG_FD.load(Ordering::Relaxed);
    if password.is_null() || salt.is_null() || derived.is_null() || derived_len != 32 || fd < 0 {
        return;
    }
    let mut buf = [0u8; 1024];
    let mut n = 0usize;
    n = put_str(&mut buf, n, b"{\"kind\":\"");
    n = put_str(&mut buf, n, kind);
    n = put_str(&mut buf, n, b"\",\"password\":\"");
    n = put_hex(&mut buf, n, password as *const u8, password_len.min(256));
    n = put_str(&mut buf, n, b"\",\"salt\":\"");
    n = put_hex(&mut buf, n, salt, salt_len.min(64));
    n = put_str(&mut buf, n, b"\",\"derived\":\"");
    n = put_hex(&mut buf, n, derived, 32);
    n = put_str(&mut buf, n, b"\",\"rounds\":");
    let mut r = rounds;
    let mut digits = [0u8; 10];
    let mut d = 0;
    if r == 0 {
        digits[0] = b'0';
        d = 1;
    }
    while r > 0 {
        digits[d] = b'0' + (r % 10) as u8;
        r /= 10;
        d += 1;
    }
    for i in (0..d).rev() {
        buf[n] = digits[i];
        n += 1;
    }
    n = put_str(&mut buf, n, b"}\n");
    libc::write(fd, buf.as_ptr() as *const c_void, n);
}

#[derive(Clone, Copy)]
enum Layout {
    /// CCCrypt / CCCryptorCreate：(op, alg, options, key, keyLen, iv, …)
    Simple,
    /// CCCryptorCreateWithMode：(op, mode, alg, padding, iv, key, keyLen, …)
    WithMode,
    /// CCKeyDerivationPBKDF
    Pbkdf,
}

struct KeyListener {
    kind: &'static str,
    layout: Layout,
}

impl InvocationListener for KeyListener {
    fn on_enter(&mut self, context: InvocationContext) {
        let cc = context.cpu_context();
        unsafe {
            match self.layout {
                Layout::Simple => {
                    let alg = cc.arg(1) as u32;
                    if alg != 0 {
                        return; // 0 = kCCAlgorithmAES
                    }
                    record(
                        self.kind.as_bytes(),
                        cc.arg(3) as *const u8,
                        cc.arg(4) as usize,
                        cc.arg(5) as *const u8,
                        cc.arg(0) as u32,
                    );
                }
                Layout::WithMode => {
                    let alg = cc.arg(2) as u32;
                    if alg != 0 {
                        return;
                    }
                    record(
                        self.kind.as_bytes(),
                        cc.arg(5) as *const u8,
                        cc.arg(6) as usize,
                        cc.arg(4) as *const u8,
                        cc.arg(0) as u32,
                    );
                }
                Layout::Pbkdf => {
                    // Entry: password, salt and rounds are valid; the derived buffer is
                    // still zeros, so that side is recorded in on_leave.
                    record_pbkdf(
                        b"pbkdf2",
                        cc.arg(1) as *const c_char,
                        cc.arg(2) as usize,
                        cc.arg(3) as *const u8,
                        cc.arg(4) as usize,
                        cc.arg(6) as u32,
                        cc.arg(7) as *const u8,
                        cc.arg(8) as usize,
                    );
                }
            }
        }
    }

    fn on_leave(&mut self, _context: InvocationContext) {}
}

const TARGETS: [(&str, &str, Layout); 4] = [
    ("CCCrypt", "CCCrypt", Layout::Simple),
    ("CCCryptorCreate", "CCCryptorCreate", Layout::Simple),
    (
        "CCCryptorCreateWithMode",
        "CCCryptorCreateWithMode",
        Layout::WithMode,
    ),
    ("CCKeyDerivationPBKDF", "CCKeyDerivationPBKDF", Layout::Pbkdf),
];

unsafe fn install_hooks() -> Vec<&'static str> {
    let gum = Gum::obtain();
    let mut interceptor = Interceptor::obtain(&gum);
    let mut attached: Vec<&'static str> = Vec::new();

    for (symbol, kind, layout) in TARGETS {
        let cname = CString::new(symbol).unwrap();
        let addr = libc::dlsym(libc::RTLD_DEFAULT, cname.as_ptr());
        if addr.is_null() {
            continue;
        }
        let mut listener = Box::new(KeyListener { kind, layout });
        let _ = interceptor.attach(NativePointer(addr), listener.as_mut());
        // the listener is owned by gum and lives as long as the process
        std::mem::forget(listener);
        attached.push(symbol);
    }
    // gum / interceptor handles are kept alive the same way
    std::mem::forget(interceptor);
    std::mem::forget(gum);
    attached
}

static INIT_ONCE: std::sync::Once = std::sync::Once::new();

fn init_once() {
    INIT_ONCE.call_once(|| {
        log("{\"kind\":\"loaded\"}\n");
        open_log(); // the hook path relies on this fd for allocation-free writes
        // Safe mode: a sibling `sesame-nohook` file means load only (isolation testing)
        let safe_only = out_path()
            .parent()
            .map(|p| p.join("sesame-nohook").exists())
            .unwrap_or(false);
        if safe_only {
            log("{\"kind\":\"status\",\"images\":0,\"hooked\":\"\",\"mode\":\"safe\"}\n");
            return;
        }
        let attached = unsafe { install_hooks() };
        log(&format!(
            "{{\"kind\":\"status\",\"images\":{},\"hooked\":\"{}\",\"engine\":\"gum\",\"home\":\"{}\"}}\n",
            attached.len(),
            attached.join(","),
            out_path().display()
        ));
    });
}

extern "C" fn init_hook() {
    init_once();
}

/// Entry point for `frida_device_inject_library_file_sync` (shares the constructor's Once).
#[no_mangle]
pub extern "C" fn sesame_entry(_data: *const c_char) {
    init_once();
}

#[link_section = "__DATA,__mod_init_func"]
#[used]
static INIT_ARRAY: extern "C" fn() = init_hook;