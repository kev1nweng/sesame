// SPDX-License-Identifier: AGPL-3.0-or-later
//! Locate the WeChat process, its version, and the database directory.

use std::path::{Path, PathBuf};

pub const CONTAINER: &str =
    "Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files";

#[derive(Debug, Clone, Default)]
pub struct Instance {
    pub pid: Option<i32>,
    pub app_path: Option<PathBuf>,
    pub version: Option<String>,
    pub db_storage: Option<PathBuf>,
    pub wxid: Option<String>,
}

pub fn find_pid() -> Option<i32> {
    for pid in crate::mach::list_pids() {
        if let Some(p) = crate::mach::pid_path(pid) {
            if p.ends_with("/WeChat.app/Contents/MacOS/WeChat") {
                return Some(pid);
            }
        }
    }
    None
}

pub fn find_app() -> Option<PathBuf> {
    let candidates = [
        PathBuf::from("/Applications/WeChat.app"),
        PathBuf::from("/Applications/WeChat.app"),
        home().join("Applications/WeChat.app"),
    ];
    candidates.into_iter().find(|p| p.exists())
}

pub fn home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/".into()))
}

pub fn read_version(app: &Path) -> Option<String> {
    let plist = app.join("Contents/Info.plist");
    let value = plist::Value::from_file(&plist).ok()?;
    value
        .as_dictionary()?
        .get("CFBundleShortVersionString")?
        .as_string()
        .map(|s| s.to_string())
}

/// Find `db_storage` inside the container; with several accounts, take the largest.
pub fn find_db_storage() -> Option<PathBuf> {
    let root = home().join(CONTAINER);
    let entries = std::fs::read_dir(&root).ok()?;
    let mut best: Option<(u64, PathBuf)> = None;
    for e in entries.flatten() {
        let dir = e.path().join("db_storage");
        if !dir.is_dir() {
            continue;
        }
        if !dir.join("message").is_dir() && !dir.join("session").is_dir() {
            continue;
        }
        let weight = dir_size(&dir.join("message")).unwrap_or(0);
        if best.as_ref().map(|(w, _)| weight > *w).unwrap_or(true) {
            best = Some((weight, dir));
        }
    }
    best.map(|(_, p)| p)
}

fn dir_size(dir: &Path) -> Option<u64> {
    let mut total = 0u64;
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        if let Ok(m) = e.metadata() {
            if m.is_file() {
                total += m.len();
            }
        }
    }
    Some(total)
}

pub fn wxid_of(db_storage: &Path) -> Option<String> {
    db_storage
        .parent()?
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
}

pub fn detect() -> Instance {
    let app_path = find_app();
    Instance {
        pid: find_pid(),
        version: app_path.as_ref().and_then(|p| read_version(p)),
        wxid: find_db_storage().as_deref().and_then(wxid_of),
        db_storage: find_db_storage(),
        app_path,
    }
}

/// SIP status. `csrutil status` is a read-only query.
pub fn sip_status() -> String {
    match std::process::Command::new("/usr/bin/csrutil")
        .arg("status")
        .output()
    {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s.is_empty() {
                String::from_utf8_lossy(&o.stderr).trim().to_string()
            } else {
                s
            }
        }
        Err(e) => format!("unavailable ({e})"),
    }
}

#[derive(Debug, Clone)]
pub struct DbFile {
    pub rel: String,
    pub path: PathBuf,
    pub size: u64,
}

/// List databases under db_storage (wal/shm skipped).
pub fn list_dbs(db_storage: &Path) -> Vec<DbFile> {
    let mut out = Vec::new();
    walk(db_storage, db_storage, &mut out);
    out.sort_by(|a, b| a.rel.cmp(&b.rel));
    out
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<DbFile>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let path = e.path();
        if path.is_dir() {
            walk(root, &path, out);
            continue;
        }
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if !name.ends_with(".db") {
            continue;
        }
        let Ok(meta) = e.metadata() else { continue };
        if meta.len() < 4096 {
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();
        out.push(DbFile {
            rel,
            path,
            size: meta.len(),
        });
    }
}