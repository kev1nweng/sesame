// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read-only key scan: no injection, no hooks, only reads the target's memory,
//! deciding whether a 32-byte window is a key by testing it against page 1 of each database.
//!
//! Compared with hooking CommonCrypto, this approach:
//!   * is independent of which crypto function WeChat calls, so it survives upgrades
//!   * injects nothing into the target process
//!   * recovers all database keys at once, without opening every feature by hand

use std::path::Path;

use rayon::prelude::*;

use crate::mach::{self, MachPort};
use crate::sqlcipher::{self, Key, IV_OFF, PAGE};
use crate::wechat::DbFile;

#[derive(Debug, Clone)]
pub struct Target {
    pub rel: String,
    pub ct: [u8; 16],
    pub iv: [u8; 16],
    pub salt: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct Hit {
    pub rel: String,
    pub key: Key,
    pub addr: u64,
}

pub fn load_targets(dbs: &[DbFile]) -> Vec<Target> {
    dbs.iter()
        .filter_map(|db| {
            let page = sqlcipher::read_page1(&db.path).ok()?;
            if page.len() != PAGE {
                return None;
            }
            let mut ct = [0u8; 16];
            let mut iv = [0u8; 16];
            let mut salt = [0u8; 16];
            ct.copy_from_slice(&page[16..32]);
            iv.copy_from_slice(&page[IV_OFF..IV_OFF + 16]);
            salt.copy_from_slice(&page[..16]);
            Some(Target {
                rel: db.rel.clone(),
                ct,
                iv,
                salt,
            })
        })
        .collect()
}

/// Search memory for a byte pattern (diagnostic: proves the read path works).
pub fn find_bytes(task: MachPort, needle: &[u8], include_readonly: bool, chunk_mb: usize) -> Vec<u64> {
    let mut out = Vec::new();
    if needle.is_empty() {
        return out;
    }
    let chunk = (chunk_mb.max(1) as u64) << 20;
    for r in mach::regions(task) {
        if !r.readable() || r.size < needle.len() as u64 {
            continue;
        }
        if !include_readonly && !r.writable() {
            continue;
        }
        let mut off = 0u64;
        while off < r.size {
            let want = (r.size - off).min(chunk);
            if let Some(buf) = mach::read_mem(task, r.addr + off, want as usize) {
                let mut i = 0usize;
                while i + needle.len() <= buf.len() {
                    if &buf[i..i + needle.len()] == needle {
                        out.push(r.addr + off + i as u64);
                        i += needle.len();
                    } else {
                        i += 1;
                    }
                }
            }
            off += want;
        }
    }
    out
}

/// Critical targets: without these there is no chat history, so scan them first.
pub fn priority(rel: &str) -> usize {
    if rel.starts_with("message/message_") && rel.ends_with(".db") && !rel.contains("fts") {
        0
    } else if rel == "contact/contact.db" || rel == "session/session.db" {
        1
    } else {
        2
    }
}

pub struct ScanStats {
    pub regions: usize,
    pub bytes: u64,
    pub candidates: u64,
}

pub fn scan(
    task: MachPort,
    targets: &[Target],
    stride: usize,
    include_readonly: bool,
    chunk_mb: usize,
) -> (Vec<Hit>, ScanStats) {
    let regions = mach::regions(task);
    let mut hits: Vec<Hit> = Vec::new();
    let mut stats = ScanStats {
        regions: 0,
        bytes: 0,
        candidates: 0,
    };
    let chunk = (chunk_mb.max(1) as u64) << 20;

    for r in regions {
        if !r.readable() || r.size < 64 {
            continue;
        }
        if !include_readonly && !r.writable() {
            continue;
        }
        stats.regions += 1;
        let mut off = 0u64;
        while off < r.size {
            let want = (r.size - off).min(chunk);
            let addr = r.addr + off;
            if let Some(buf) = mach::read_mem(task, addr, want.min(usize::MAX as u64) as usize) {
                stats.bytes += buf.len() as u64;
                let n = if buf.len() >= 32 {
                    (buf.len() - 32) / stride + 1
                } else {
                    0
                };
                stats.candidates += n as u64;
                let found: Vec<Hit> = (0..n)
                    .into_par_iter()
                    .filter_map(|i| {
                        let o = i * stride;
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&buf[o..o + 32]);
                        for t in targets {
                            if sqlcipher::quick_match(&key, &t.ct, &t.iv) {
                                return Some(Hit {
                                    rel: t.rel.clone(),
                                    key,
                                    addr: addr + o as u64,
                                });
                            }
                        }
                        None
                    })
                    .collect();
                hits.extend(found);
            }
            off += want;
        }
    }
    (hits, stats)
}

/// Strict verification after a hit: full page-1 decrypt plus per-database matching.
pub fn verify(db_root: &Path, targets: &[Target], hits: &[Hit]) -> Vec<Hit> {
    let mut out: Vec<Hit> = Vec::new();
    for h in hits {
        let Some(t) = targets.iter().find(|t| t.rel == h.rel) else {
            continue;
        };
        let path = db_root.join(&t.rel);
        let Ok(page) = sqlcipher::read_page1(&path) else {
            continue;
        };
        if !sqlcipher::header_ok(&page, &h.key) {
            continue;
        }
        if out
            .iter()
            .any(|o| o.rel == h.rel && o.key == h.key)
        {
            continue;
        }
        out.push(h.clone());
    }
    out
}