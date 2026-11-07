// SPDX-License-Identifier: AGPL-3.0-or-later
//! sesame — WeChat for macOS databases: key extraction / decryption / export.

mod export;
mod fav;
mod inject;
mod mach;
mod scan;
mod sns;
mod sqlcipher;
mod util;
mod wechat;
mod xml;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(
    name = "sesame",
    version,
    about = "WeChat for macOS databases: key extraction / decryption / export",
    long_about = "Read-only: extracts SQLCipher keys from a running WeChat process, \
                   decrypts the local databases, and exports readable chat history. \
                   WeChat and the original databases are never modified."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Diagnose the environment: SIP status, memory access, WeChat version, database location
    Doctor,
    /// Re-sign this binary with debug entitlements (needed to read memory without root)
    Sign,
    /// Diagnostic: search WeChat memory for a string (verifies the read path)
    Find {
        /// Text to search for; with --hex, a hex string
        text: String,
        /// Treat text as a hex byte string
        #[arg(long)]
        hex: bool,
        #[arg(long)]
        pid: Option<i32>,
        #[arg(long)]
        include_readonly: bool,
        #[arg(long, default_value_t = 64)]
        chunk_mb: usize,
        /// Bytes of context to dump around each hit
        #[arg(long, default_value_t = 48)]
        context: usize,
    },
    /// Read-only scan of WeChat's memory for database keys
    Scan {
        /// WeChat pid (auto-detected by default)
        #[arg(long)]
        pid: Option<i32>,
        /// db_storage directory (auto-detected by default)
        #[arg(long)]
        db_dir: Option<PathBuf>,
        /// Output file
        #[arg(long, default_value = "keys.json")]
        out: PathBuf,
        /// Scan step in bytes. 4 is safest; 8 is faster but may miss
        #[arg(long, default_value_t = 4)]
        stride: usize,
        /// Scan every database (default: messages, contacts, sessions only)
        #[arg(long)]
        all: bool,
        /// Also scan read-only regions (slow, rarely needed)
        #[arg(long)]
        include_readonly: bool,
        /// Read size per chunk
        #[arg(long, default_value_t = 64)]
        chunk_mb: usize,
    },
    /// Inject the hook library and capture keys at runtime (no memory scan)
    Hook {
        #[arg(long)]
        pid: Option<i32>,
        #[arg(long)]
        db_dir: Option<PathBuf>,
        #[arg(long, default_value = "keys.json")]
        out: PathBuf,
        /// Capture window in seconds
        #[arg(long, default_value_t = 120)]
        seconds: u64,
        /// Path to libsesame_hook.dylib (defaults to the same directory)
        #[arg(long)]
        dylib: Option<PathBuf>,
        /// Loader: frida (default, recommended) / builtin (debug only; crashes WeChat)
        #[arg(long, default_value = "frida")]
        loader: String,
        /// Inject into the running WeChat instead of restarting it.
        /// Without this flag the command quits WeChat, relaunches it, injects at the
        /// login screen and waits for you to sign in, which is the only way to capture
        /// every database key.
        #[arg(long)]
        attach: bool,
    },
    /// Inject only, no capture (debugging)
    Inject {
        #[arg(long)]
        pid: i32,
        /// Library path
        dylib: Option<PathBuf>,
    },
    /// Import keys from a hook log (jsonl) and match them to databases
    Import {
        /// Hook log path
        log: PathBuf,
        #[arg(long)]
        db_dir: Option<PathBuf>,
        #[arg(long, default_value = "keys.json")]
        out: PathBuf,
    },
    /// Decrypt databases using keys.json
    Decrypt {
        #[arg(long, default_value = "keys.json")]
        keys: PathBuf,
        #[arg(long)]
        db_dir: Option<PathBuf>,
        #[arg(long, default_value = "decrypted")]
        out: PathBuf,
    },
    /// Export decrypted databases as readable chat history
    Export {
        #[arg(long, default_value = "decrypted")]
        dec_root: PathBuf,
        #[arg(long, default_value = "export")]
        out: PathBuf,
        #[arg(long, default_value_t = 1)]
        min_messages: usize,
    },
    /// Export Moments (requires a decrypted sns.db)
    Sns {
        #[arg(long, default_value = "decrypted")]
        dec_root: PathBuf,
        #[arg(long, default_value = "export_sns")]
        out: PathBuf,
    },
    /// Export Favorites (requires a decrypted favorite.db)
    Fav {
        #[arg(long, default_value = "decrypted")]
        dec_root: PathBuf,
        #[arg(long, default_value = "export_fav")]
        out: PathBuf,
    },
    /// Full pipeline: capture keys -> decrypt -> export chats / Moments / Favorites
    All {
        /// Capture window in seconds (starts after login)
        #[arg(long, default_value_t = 180)]
        seconds: u64,
        #[arg(long)]
        db_dir: Option<PathBuf>,
        #[arg(long, default_value = "keys.json")]
        keys: PathBuf,
        #[arg(long, default_value = "decrypted")]
        dec_root: PathBuf,
        #[arg(long, default_value = "export")]
        out: PathBuf,
        /// Inject into the running WeChat instead of restarting it.
        /// The default is: quit WeChat, relaunch, inject at the login screen, wait for
        /// you to sign in.
        #[arg(long)]
        attach: bool,
    },
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct WechatInfo {
    version: Option<String>,
    wxid: Option<String>,
    pid: Option<i32>,
    app: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct DbKey {
    key: String,
    salt: String,
    size: u64,
}

#[derive(Serialize, Deserialize, Default)]
struct KeyFile {
    tool: String,
    created_at: String,
    wechat: WechatInfo,
    databases: BTreeMap<String, DbKey>,
    #[serde(default)]
    unmatched: Vec<String>,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Doctor => doctor(),
        Cmd::Sign => sign_self(),
        Cmd::Find {
            text,
            hex,
            pid,
            include_readonly,
            chunk_mb,
            context,
        } => find_cmd(text, hex, pid, include_readonly, chunk_mb, context),
        Cmd::Scan {
            pid,
            db_dir,
            out,
            stride,
            all,
            include_readonly,
            chunk_mb,
        } => scan_cmd(pid, db_dir, out, stride, all, include_readonly, chunk_mb),
        Cmd::Import { log, db_dir, out } => import_cmd(log, db_dir, out),
        Cmd::Inject { pid, dylib } => inject_cmd(pid, dylib),
        Cmd::Hook {
            pid,
            db_dir,
            out,
            seconds,
            dylib,
            loader,
            attach,
        } => hook_cmd(pid, db_dir, out, seconds, dylib, loader, attach),
        Cmd::Decrypt { keys, db_dir, out } => decrypt_cmd(keys, db_dir, out),
        Cmd::Export {
            dec_root,
            out,
            min_messages,
        } => export::run(&dec_root, &out, min_messages),
        Cmd::Sns { dec_root, out } => sns::run(&dec_root, &out),
        Cmd::All {
            seconds,
            db_dir,
            keys,
            dec_root,
            out,
            attach,
        } => all_cmd(seconds, db_dir, keys, dec_root, out, attach),
        Cmd::Fav { dec_root, out } => fav::run(&dec_root, &out),
    }
}

fn resolve_db_dir(arg: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = arg {
        anyhow::ensure!(p.is_dir(), "directory not found: {}", p.display());
        return Ok(p);
    }
    wechat::find_db_storage().ok_or_else(|| {
        anyhow::anyhow!("WeChat db_storage not found; pass --db-dir (see `sesame doctor`)")
    })
}

/// Re-sign this binary ad-hoc with debug entitlements.
/// This is what makes non-root memory reads possible: the kernel checks the caller's entitlements.
fn sign_self() -> Result<()> {
    let exe = std::env::current_exe()?;
    let ent = std::env::temp_dir().join("sesame-debug.entitlements");
    std::fs::write(
        &ent,
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.security.cs.debugger</key><true/>
<key>com.apple.security.get-task-allow</key><true/>
</dict></plist>
"#,
    )?;
    let status = std::process::Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", "--entitlements"])
        .arg(&ent)
        .arg(&exe)
        .status()?;
    anyhow::ensure!(status.success(), "codesign failed");
    println!("added debug entitlements to {}", exe.display());
    println!("you can now run `sesame scan` as a normal user. Re-sign after every rebuild.");
    Ok(())
}

fn find_cmd(
    text: String,
    hex: bool,
    pid: Option<i32>,
    include_readonly: bool,
    chunk_mb: usize,
    context: usize,
) -> Result<()> {
    let needle: Vec<u8> = if hex {
        let cleaned: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        anyhow::ensure!(cleaned.len() % 2 == 0, "hex string must have an even length");
        (0..cleaned.len() / 2)
            .map(|i| u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16))
            .collect::<Result<Vec<u8>, _>>()?
    } else {
        text.as_bytes().to_vec()
    };

    let info = wechat::detect();
    let pid = pid.or(info.pid).ok_or_else(|| anyhow::anyhow!("WeChat is not running"))?;
    let task = mach::task_for(pid)
        .map_err(|c| anyhow::anyhow!("cannot read memory ({c}); run `sesame sign` or use sudo"))?;
    let started = Instant::now();
    let hits = scan::find_bytes(task, &needle, include_readonly, chunk_mb);
    println!(
        "found {} hits in pid {pid} memory (pattern {} bytes, {:.1}s)",
        hits.len(),
        needle.len(),
        started.elapsed().as_secs_f64()
    );
    for a in hits.iter().take(12) {
        println!("  0x{a:x}");
        if context > 0 {
            let start = a.saturating_sub(context as u64);
            let want = context * 2 + needle.len();
            if let Some(buf) = mach::read_mem(task, start, want) {
                for (i, chunk) in buf.chunks(16).enumerate() {
                    let hexs: String = chunk.iter().map(|b| format!("{b:02x}")).collect();
                    let ascii: String = chunk
                        .iter()
                        .map(|b| if (0x20..0x7f).contains(b) { *b as char } else { '.' })
                        .collect();
                    println!(
                        "     0x{:012x}  {:<32}  |{}|",
                        start + (i * 16) as u64,
                        hexs,
                        ascii
                    );
                }
            }
        }
    }
    Ok(())
}

fn doctor() -> Result<()> {
    println!("== environment ==");
    println!("SIP         : {}", wechat::sip_status());
    let info = wechat::detect();
    println!(
        "WeChat      : {}",
        info.version.clone().unwrap_or_else(|| "not installed / unrecognised".into())
    );
    if let Some(app) = &info.app_path {
        println!("App path    : {}", app.display());
    }
    match info.pid {
        Some(pid) => {
            let rss = mach::rss_bytes(pid)
                .map(util::human_mb)
                .unwrap_or_else(|| "?".into());
            println!("process     : pid {pid}, resident {rss}");
        }
        None => println!("process     : not running (open WeChat and sign in first)"),
    }
    match &info.db_storage {
        Some(p) => {
            let dbs = wechat::list_dbs(p);
            let total: u64 = dbs.iter().map(|d| d.size).sum();
            println!("data dir    : {}", p.display());
            println!(
                "databases   : {} files, {}",
                dbs.len(),
                util::human_mb(total)
            );
        }
        None => println!("data dir    : not found"),
    }

    println!("\n== capability checks ==");
    let Some(pid) = info.pid else {
        println!("memory read : skipped (WeChat not running)");
        return Ok(());
    };
    match mach::task_for(pid) {
        Ok(task) => {
            println!("memory read : ok (task port acquired)");
            let regions = mach::regions(task);
            let writable: u64 = regions
                .iter()
                .filter(|r| r.readable() && r.writable())
                .map(|r| r.size)
                .sum();
            println!(
                "scannable   : {} regions, {} writable",
                regions.len(),
                util::human_mb(writable)
            );
        }
        Err(code) => {
            println!("memory read : failed (kernel returned {code})");
            println!("  options:");
            println!("  1) disable SIP: `csrutil disable` in Recovery mode, then reboot");
            println!("  2) run with sudo (root can read directly when SIP is off)");
            println!("  3) keep SIP: re-sign the WeChat binary with get-task-allow, restart it");
        }
    }

    if let Some(p) = &info.db_storage {
        println!("\n== file access ==");
        let dbs = wechat::list_dbs(p);
        if let Some(first) = dbs.iter().find(|d| d.rel.starts_with("message/message_")) {
            match sqlcipher::read_page1(&first.path) {
                Ok(_) => println!("read database : ok ({})", first.rel),
                Err(e) => {
                    println!("read database : failed ({e})");
                    println!("  the terminal may need Full Disk Access");
                }
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn scan_cmd(
    pid: Option<i32>,
    db_dir: Option<PathBuf>,
    out: PathBuf,
    stride: usize,
    all: bool,
    include_readonly: bool,
    chunk_mb: usize,
) -> Result<()> {
    let db_root = resolve_db_dir(db_dir)?;
    let info = wechat::detect();
    let dbs = wechat::list_dbs(&db_root);
    if dbs.is_empty() {
        bail!("no databases found under {}", db_root.display());
    }

    let selected: Vec<_> = dbs
        .iter()
        .filter(|d| all || scan::priority(&d.rel) <= 1)
        .cloned()
        .collect();
    let targets = scan::load_targets(&selected);
    if targets.is_empty() {
        bail!("cannot read the database header; check permissions (Full Disk Access may help)");
    }
    println!(
        "targets     : {} / {} databases ({})",
        targets.len(),
        dbs.len(),
        if all { "all" } else { "critical only; --all scans everything" }
    );

    let pid = pid.or(info.pid).ok_or_else(|| {
        anyhow::anyhow!("WeChat is not running. Open it, sign in, or pass --pid")
    })?;
    let task = mach::task_for(pid).map_err(|code| {
        anyhow::anyhow!(
            "cannot read WeChat process memory (kernel returned {code}).\n\
             Fix: disable SIP, run with sudo, or re-sign WeChat with get-task-allow.\n\
             Run `sesame doctor` for a full diagnosis."
        )
    })?;

    println!("scanning    : pid {pid}, stride {stride}");
    let started = Instant::now();
    let (hits, stats) = scan::scan(task, &targets, stride, include_readonly, chunk_mb);
    let elapsed = started.elapsed().as_secs_f64();
    println!(
        "done        : read {} of memory / {} candidates, {} hits, {:.1}s",
        util::human_mb(stats.bytes),
        stats.candidates,
        hits.len(),
        elapsed
    );

    let verified = scan::verify(&db_root, &targets, &hits);
    let mut file = KeyFile {
        tool: format!("sesame {}", env!("CARGO_PKG_VERSION")),
        created_at: util::now_str(),
        wechat: WechatInfo {
            version: info.version.clone(),
            wxid: info.wxid.clone(),
            pid: Some(pid),
            app: info.app_path.as_ref().map(|p| p.display().to_string()),
        },
        databases: BTreeMap::new(),
        unmatched: Vec::new(),
    };

    for hit in &verified {
        let Some(db) = selected.iter().find(|d| d.rel == hit.rel) else {
            continue;
        };
        let salt = sqlcipher::read_page1(&db.path)
            .map(|p| p[..16].to_vec())
            .unwrap_or_default();
        file.databases.insert(
            hit.rel.clone(),
            DbKey {
                key: hit.key.iter().map(|b| format!("{b:02x}")).collect(),
                salt: salt.iter().map(|b| format!("{b:02x}")).collect(),
                size: db.size,
            },
        );
    }
    file.unmatched = dbs
        .iter()
        .filter(|d| !file.databases.contains_key(&d.rel))
        .map(|d| d.rel.clone())
        .collect();

    std::fs::write(&out, serde_json::to_vec_pretty(&file)?)?;

    println!("\ndatabases with keys:");
    for (rel, k) in &file.databases {
        println!("  ✓ {rel:<34} {}", &k.key[..16]);
    }
    if !file.unmatched.is_empty() {
        println!("\nwithout keys: {}", file.unmatched.join(", "));
        println!("(rescan with --all, or run again: database pages get swapped in and out)");
    }
    println!("\nwritten to {}", out.display());
    Ok(())
}

fn inject_cmd(pid: i32, dylib: Option<PathBuf>) -> Result<()> {
    let src = match dylib {
        Some(p) => p,
        None => std::env::current_exe()?
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("libsesame_hook.dylib"),
    };
    anyhow::ensure!(src.exists(), "not found: {}", src.display());
    inject::inject(pid, src.to_str().unwrap())?;
    println!("injected {}", src.display());
    Ok(())
}

/// Wait for the hook's status line, confirming the hooks really installed.
fn wait_for_status(log: &Path, timeout: std::time::Duration) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Ok(s) = std::fs::read_to_string(log) {
            if s.contains("\"kind\":\"status\"") {
                return Ok(());
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    anyhow::bail!(
        "waited {}s for the status line; injection may have failed (log: {})",
        timeout.as_secs(),
        log.display()
    )
}

/// Restart WeChat: quit cleanly, relaunch, stop at the login screen.
fn restart_wechat() -> Result<i32> {
    if wechat::detect().pid.is_some() {
        println!("restarting WeChat (you will need to sign in again)");
        let _ = std::process::Command::new("/usr/bin/osascript")
            .args(["-e", r#"quit app "WeChat""#])
            .status();
        let start = Instant::now();
        while start.elapsed() < std::time::Duration::from_secs(25) && wechat::detect().pid.is_some() {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        if let Some(pid) = wechat::detect().pid {
            println!("  graceful quit timed out; killing {pid}");
            let _ = std::process::Command::new("/bin/kill")
                .args(["-9", &pid.to_string()])
                .status();
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
    }
    std::process::Command::new("/usr/bin/open")
        .args(["-a", "/Applications/WeChat.app"])
        .status()?;
    let start = Instant::now();
    while start.elapsed() < std::time::Duration::from_secs(60) && wechat::detect().pid.is_none() {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let pid = wechat::detect().pid;
    anyhow::ensure!(pid.is_some(), "WeChat did not start");
    println!("  waiting for the login screen (15s)");
    std::thread::sleep(std::time::Duration::from_secs(15));
    Ok(pid.unwrap())
}

fn all_cmd(
    seconds: u64,
    db_dir: Option<PathBuf>,
    keys: PathBuf,
    dec_root: PathBuf,
    out: PathBuf,
    attach: bool,
) -> Result<()> {
    println!("\n== 1/4 capture keys ==");
    hook_cmd(None, db_dir.clone(), keys.clone(), seconds, None, "frida".into(), attach)?;

    println!("\n== 2/4 decrypt ==");
    decrypt_cmd(keys, db_dir, dec_root.clone())?;

    println!("\n== 3/4 export chats ==");
    export::run(&dec_root, &out.join("chat"), 1)?;

    println!("\n== 4/4 export Moments / Favorites ==");
    if let Err(e) = sns::run(&dec_root, &out.join("sns")) {
        println!("Moments skipped: {e}");
    }
    if let Err(e) = fav::run(&dec_root, &out.join("favorite")) {
        println!("Favorites skipped: {e}");
    }
    println!("\nall done: {}", out.display());
    Ok(())
}

fn hook_cmd(
    pid: Option<i32>,
    db_dir: Option<PathBuf>,
    out: PathBuf,
    seconds: u64,
    dylib: Option<PathBuf>,
    loader: String,
    attach: bool,
) -> Result<()> {
    // Default path: quit WeChat, relaunch it, inject while the login screen is still up.
    // WeChat unlocks every database exactly once, at login, so that is the only moment
    // where all keys exist.
    let pid = if attach {
        let info = wechat::detect();
        pid.or(info.pid).ok_or_else(|| {
            anyhow::anyhow!("WeChat is not running; drop --attach to let sesame start it")
        })?
    } else {
        if pid.is_some() {
            println!("note: --pid is ignored unless --attach is given");
        }
        restart_wechat()?
    };
    let db_root = resolve_db_dir(db_dir)?;
    let info = wechat::detect();

    // Data dir = four levels up from db_storage (db_storage/<wxid>/xwechat_files/Documents/Data)
    let data_dir = db_root
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("cannot derive the container directory from {}", db_root.display()))?
        .to_path_buf();

    let src = match dylib {
        Some(p) => p,
        None => std::env::current_exe()?
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("libsesame_hook.dylib"),
    };
    anyhow::ensure!(
        src.exists(),
        "hook library not found: {} (build it with `cargo build --release`, or pass --dylib)",
        src.display()
    );

    // copy inside WeChat's container: the sandbox only lets it read its own directory
    let dest_dir = data_dir.join("tmp").join("sesame");
    std::fs::create_dir_all(&dest_dir)?;
    let dest = dest_dir.join("libsesame_hook.dylib");
    std::fs::copy(&src, &dest)?;
    let st = std::process::Command::new("/usr/bin/codesign")
        .args(["--force", "-s", "-"])
        .arg(&dest)
        .status()?;
    anyhow::ensure!(st.success(), "signing the hook library failed");

    let log = data_dir.join("sesame-keys.jsonl");
    let _ = std::fs::remove_file(&log);

    println!("injecting -> pid {pid}");

    // two loaders:
    //   frida   - frida-core attach + script dlopen; the stable option for WeChat;
    //   builtin - our own Mach injector; fine for ordinary processes, risky for WeChat.
    if loader == "builtin" {
        println!("loader: builtin Mach injector");
        inject::inject_watched(
            pid,
            dest.to_str().unwrap(),
            Some(&log),
            std::time::Duration::from_secs(30),
        )?;
    } else {
        println!("loader: frida-core {}", sesame_load::version());
        sesame_load::inject_library(pid as u32, &dest)?;
        // wait for the status line (dlopen can take seconds inside a large app)
        wait_for_status(&log, std::time::Duration::from_secs(30))?;
    }
    if !attach {
        println!("hooks are in place. Sign in to WeChat now (login unlocks every database once).");
        let started = Instant::now();
        let mut logged = false;
        while started.elapsed() < std::time::Duration::from_secs(900) {
            if let Ok(txt) = std::fs::read_to_string(&log) {
                if txt.contains("\"key\":\"") {
                    logged = true;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        anyhow::ensure!(logged, "no login within 15 minutes; capture cancelled (hooks remain, run `sesame import` later)");
        println!("login detected, capturing for {seconds}s.");
    } else {
        println!(
            "capturing for {seconds}s. Attach mode only sees the databases you open yourself;"
        );
        println!("drop --attach to restart WeChat and capture every key at login.");
    }

    let started = Instant::now();
    let mut keys: BTreeMap<String, String> = BTreeMap::new();
    let mut status_seen = false;
    let mut pbkdf_count = 0usize;
    while started.elapsed().as_secs() < seconds {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let Ok(text) = std::fs::read_to_string(&log) else {
            continue;
        };
        for line in text.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            match v.get("kind").and_then(|k| k.as_str()) {
                Some("status") => {
                    if !status_seen {
                        status_seen = true;
                        println!(
                            "hooks installed: {} ({} images scanned)",
                            v.get("hooked").and_then(|x| x.as_str()).unwrap_or("?"),
                            v.get("images").and_then(|x| x.as_u64()).unwrap_or(0)
                        );
                    }
                }
                Some("pbkdf2") => {
                    pbkdf_count += 1;
                    println!("  * password derivation seen (rounds={})", v.get("rounds").and_then(|x| x.as_u64()).unwrap_or(0));
                }
                Some(kind) => {
                    if let Some(k) = v.get("key").and_then(|x| x.as_str()) {
                        if !keys.contains_key(k) {
                            println!("  + key {}... from {kind}", &k[..12.min(k.len())]);
                            keys.insert(
                                k.to_string(),
                                v.get("iv").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                            );
                        }
                    }
                }
                None => {}
            }
        }
    }

    if !status_seen {
        println!("\nno status line seen; injection may have failed. Diagnose with `sesame doctor`.");
    }
    if keys.is_empty() {
        bail!(
            "no keys captured: WeChat decrypted no database pages during the window. \
             Keep WeChat in the foreground, open a few chats, or raise --seconds."
        );
    }

    // match keys to databases
    let dbs = wechat::list_dbs(&db_root);
    let mut file = KeyFile {
        tool: format!("sesame {} (hook)", env!("CARGO_PKG_VERSION")),
        created_at: util::now_str(),
        wechat: WechatInfo {
            version: info.version.clone(),
            wxid: info.wxid.clone(),
            pid: Some(pid),
            app: info.app_path.as_ref().map(|p| p.display().to_string()),
        },
        databases: BTreeMap::new(),
        unmatched: Vec::new(),
    };
    for khex in keys.keys() {
        let key = hex_to_key(khex)?;
        for db in &dbs {
            if file.databases.contains_key(&db.rel) {
                continue;
            }
            let Ok(head) = sqlcipher::read_head(&db.path, 16384) else {
                continue;
            };
            if sqlcipher::Layout::detect(&head, &key).is_some() {
                file.databases.insert(
                    db.rel.clone(),
                    DbKey {
                        key: khex.clone(),
                        salt: head[..16].iter().map(|b| format!("{b:02x}")).collect(),
                        size: db.size,
                    },
                );
            }
        }
    }
    file.unmatched = dbs
        .iter()
        .filter(|d| !file.databases.contains_key(&d.rel))
        .map(|d| d.rel.clone())
        .collect();
    std::fs::write(&out, serde_json::to_vec_pretty(&file)?)?;

    println!("\nmatch result: {}/{} databases have keys", file.databases.len(), dbs.len());
    for (rel, k) in &file.databases {
        println!("  ✓ {rel:<34} {}", &k.key[..16]);
    }
    if pbkdf_count > 0 {
        println!("also saw {pbkdf_count} password derivations, useful for uncovered databases.");
    }
    println!("written to {}", out.display());
    Ok(())
}

fn import_cmd(log_path: PathBuf, db_dir: Option<PathBuf>, out: PathBuf) -> Result<()> {
    let db_root = resolve_db_dir(db_dir)?;
    let text = std::fs::read_to_string(&log_path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", log_path.display()))?;

    let mut keys: BTreeMap<String, String> = BTreeMap::new();
    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if let Some(k) = v.get("key").and_then(|x| x.as_str()) {
            keys.insert(k.to_string(), String::new());
        }
    }
    anyhow::ensure!(!keys.is_empty(), "no keys in {}", log_path.display());
    println!("log contains {} distinct keys; matching databases", keys.len());

    let dbs = wechat::list_dbs(&db_root);
    let info = wechat::detect();
    let mut file = KeyFile {
        tool: format!("sesame {} (gum hook import)", env!("CARGO_PKG_VERSION")),
        created_at: util::now_str(),
        wechat: WechatInfo {
            version: info.version.clone(),
            wxid: info.wxid.clone(),
            pid: info.pid,
            app: info.app_path.as_ref().map(|p| p.display().to_string()),
        },
        databases: BTreeMap::new(),
        unmatched: Vec::new(),
    };

    for khex in keys.keys() {
        let key = hex_to_key(khex)?;
        for db in &dbs {
            if file.databases.contains_key(&db.rel) {
                continue;
            }
            let Ok(head) = sqlcipher::read_head(&db.path, 16384) else {
                continue;
            };
            if sqlcipher::Layout::detect(&head, &key).is_some() {
                file.databases.insert(
                    db.rel.clone(),
                    DbKey {
                        key: khex.clone(),
                        salt: head[..16].iter().map(|b| format!("{b:02x}")).collect(),
                        size: db.size,
                    },
                );
            }
        }
    }
    file.unmatched = dbs
        .iter()
        .filter(|d| !file.databases.contains_key(&d.rel))
        .map(|d| d.rel.clone())
        .collect();
    std::fs::write(&out, serde_json::to_vec_pretty(&file)?)?;

    println!("matched: {}/{} databases", file.databases.len(), dbs.len());
    for (rel, k) in &file.databases {
        println!("  ✓ {rel:<34} {}", &k.key[..16]);
    }
    if !file.unmatched.is_empty() {
        println!("unmatched: {}", file.unmatched.join(", "));
    }
    println!("written to {}", out.display());
    Ok(())
}

fn decrypt_cmd(keys: PathBuf, db_dir: Option<PathBuf>, out: PathBuf) -> Result<()> {
    let db_root = resolve_db_dir(db_dir)?;
    let text = std::fs::read_to_string(&keys)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", keys.display()))?;
    let file: KeyFile = serde_json::from_str(&text)?;
    if file.databases.is_empty() {
        bail!("no keys in {}", keys.display());
    }

    let mut ok_count = 0;
    let mut bad: Vec<String> = Vec::new();
    for (rel, entry) in &file.databases {
        let key = hex_to_key(&entry.key)?;
        let src = db_root.join(rel);
        let dst = out.join(rel);
        let layout = sqlcipher::read_head(&src, 16384)
            .ok()
            .and_then(|h| sqlcipher::Layout::detect(&h, &key))
            .unwrap_or_default();
        match sqlcipher::decrypt_db_with(&src, &dst, &key, layout) {
            Ok(pages) => {
                let good = sqlcipher::sqlite_ok(&dst);
                println!(
                    "{:<34} {:>7} pages  {:>8}  {}",
                    rel,
                    pages,
                    util::human_mb(dst.metadata().map(|m| m.len()).unwrap_or(0)),
                    if good { "ok  quick_check" } else { "!   quick_check failed" }
                );
                if good {
                    ok_count += 1;
                } else {
                    bad.push(rel.clone());
                }
            }
            Err(e) => println!("{:<34} decrypt failed: {e}", rel),
        }
    }
    println!("\ndone: {} / {} databases passed quick_check", ok_count, file.databases.len());
    if !bad.is_empty() {
        println!("failed: {}", bad.join(", "));
    }
    Ok(())
}

fn hex_to_key(s: &str) -> Result<[u8; 32]> {
    let cleaned: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    anyhow::ensure!(cleaned.len() == 64, "wrong key length");
    let mut key = [0u8; 32];
    for i in 0..32 {
        key[i] = u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16)?;
    }
    Ok(key)
}

#[allow(dead_code)]
fn unused_path_check(_: &Path) {}