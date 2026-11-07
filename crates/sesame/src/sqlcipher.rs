// SPDX-License-Identifier: AGPL-3.0-or-later
//! SQLCipher 4 page layout and decryption (WeChat 4.x parameters).
//!
//! Layout measured on real data (differs from common writeups; verified with `PRAGMA quick_check`):
//!
//! ```text
//! first 16 bytes of file = salt
//! page 1: salt(16) + AES(plaintext[16:4016]) + IV(16) + HMAC(64) = 4096
//! page n:           AES(plaintext[0:4016])  + IV(16) + HMAC(64) = 4096
//! ```
//!
//! The IV sits at `[4016, 4032)` in every page, so each page decrypts independently.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use anyhow::{Context, Result};

pub const PAGE: usize = 4096;
pub const RESERVE: usize = 80;
pub const IV_OFF: usize = PAGE - RESERVE; // 4016
pub const MAGIC: &[u8; 16] = b"SQLite format 3\0";

pub type Key = [u8; 32];

/// Geometry of one page.
/// WeChat 4.x uses 4096/80, but hardcoding these two numbers was the only structural
/// assumption in this project, so they are detected instead: version changes need no edits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub page: usize,
    pub reserve: usize,
}

impl Default for Layout {
    fn default() -> Self {
        Layout { page: PAGE, reserve: RESERVE }
    }
}

/// Detection order: the common case first, then other combinations.
const PAGE_CANDIDATES: [usize; 4] = [4096, 1024, 8192, 16384];
const RESERVE_CANDIDATES: [usize; 5] = [80, 96, 48, 64, 32];

impl Layout {
    #[inline]
    pub fn iv_off(&self) -> usize {
        self.page - self.reserve
    }

    /// Whether the first 16 plaintext bytes match a SQLite header for this layout.
    #[inline]
    fn header_ok_at(&self, pt: &[u8]) -> bool {
        if pt.len() < 16 {
            return false;
        }
        pt[0] == 0x10
            && pt[1] == 0x00
            && (pt[2] == 1 || pt[2] == 2)
            && (pt[3] == 1 || pt[3] == 2)
            && pt[4] == self.reserve as u8
            && pt[5] == 0x40
            && pt[6] == 0x20
            && pt[7] == 0x20
    }

    /// Decrypt one page with this layout. Page 1 gets the SQLite magic restored.
    pub fn decrypt_page(&self, page: &[u8], key: &Key, pgno: u32) -> Vec<u8> {
        let iv_off = self.iv_off();
        if page.len() < self.page || iv_off + 16 > page.len() {
            return Vec::new();
        }
        let iv = &page[iv_off..iv_off + 16];
        let ct = if pgno == 1 { &page[16..iv_off] } else { &page[0..iv_off] };
        let mut buf = ct.to_vec();
        let dec = cbc::Decryptor::<Aes256>::new(
            GenericArray::from_slice(key),
            GenericArray::from_slice(iv),
        );
        let Some(plain) = dec.decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf).ok()
        else {
            return Vec::new();
        };
        let mut out = Vec::with_capacity(self.page);
        if pgno == 1 {
            out.extend_from_slice(MAGIC);
        }
        out.extend_from_slice(plain);
        out.resize(self.page, 0);
        out
    }

    /// Full page-1 validation.
    pub fn header_ok(&self, page1: &[u8], key: &Key) -> bool {
        let plain = self.decrypt_page(page1, key, 1);
        plain.len() >= 24
            && plain[..16] == *MAGIC
            && plain[16] == 0x10
            && plain[17] == 0x00
            && plain[20] == self.reserve as u8
            && self.page_size_field_ok(&plain)
    }

    /// The header's page-size field (offset 16, big endian; 1 means 65536) must match.
    fn page_size_field_ok(&self, plain: &[u8]) -> bool {
        let v = u16::from_be_bytes([plain[16], plain[17]]) as usize;
        let actual = if v == 1 { 65536 } else { v };
        actual == self.page
    }

    /// Fast check: decrypt only the first block, no full-page CBC.
    pub fn quick_match(&self, key: &Key, ct: &[u8], iv: &[u8]) -> bool {
        if ct.len() < 16 || iv.len() < 16 {
            return false;
        }
        let cipher = Aes256::new(GenericArray::from_slice(key));
        let mut block = GenericArray::clone_from_slice(&ct[..16]);
        cipher.decrypt_block(&mut block);
        let mut pt = [0u8; 16];
        for i in 0..16 {
            pt[i] = block[i] ^ iv[i];
        }
        self.header_ok_at(&pt)
    }

    /// Given raw page-1 bytes (at least 16384) and a key, infer the layout.
    pub fn detect(head: &[u8], key: &Key) -> Option<Layout> {
        for page in PAGE_CANDIDATES {
            for reserve in RESERVE_CANDIDATES {
                if head.len() < page {
                    continue;
                }
                let l = Layout { page, reserve };
                if l.header_ok(head, key) {
                    return Some(l);
                }
            }
        }
        None
    }
}

/// Read the first N bytes of a file (for detection).
pub fn read_head(path: &Path, n: usize) -> Result<Vec<u8>> {
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut buf = vec![0u8; n];
    let got = f.read(&mut buf)?;
    buf.truncate(got);
    Ok(buf)
}

/// Default-layout check for a single page.

/// Fast check: does this key decrypt the first block with the given IV?
#[inline]
pub fn quick_match(key: &Key, ct: &[u8], iv: &[u8]) -> bool {
    Layout::default().quick_match(key, ct, iv)
}

/// Decrypt one page (default layout).
pub fn decrypt_page(page: &[u8], key: &Key, pgno: u32) -> Vec<u8> {
    Layout::default().decrypt_page(page, key, pgno)
}

pub fn read_page1(path: &Path) -> Result<Vec<u8>> {
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut buf = vec![0u8; PAGE];
    let n = f.read(&mut buf)?;
    buf.truncate(n);
    anyhow::ensure!(buf.len() == PAGE, "file is smaller than one page");
    Ok(buf)
}

/// Full page-1 validation (default layout).
pub fn header_ok(page1: &[u8], key: &Key) -> bool {
    Layout::default().header_ok(page1, key)
}

/// Decrypt a whole database (default layout).
pub fn decrypt_db(src: &Path, dst: &Path, key: &Key) -> Result<usize> {
    decrypt_db_with(src, dst, key, Layout::default())
}

/// Decrypt a whole database with explicit layout. Merges committed pages from `-wal`.
pub fn decrypt_db_with(src: &Path, dst: &Path, key: &Key, layout: Layout) -> Result<usize> {
    let total = std::fs::metadata(src)?.len() as usize / layout.page;
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = dst.with_extension("part");
    {
        let mut fi = File::open(src)?;
        let mut fo = File::create(&tmp)?;
        let mut page = vec![0u8; layout.page];
        for pgno in 1..=total {
            let n = fi.read(&mut page)?;
            if n < layout.page {
                break;
            }
            let plain = layout.decrypt_page(&page, key, pgno as u32);
            if plain.is_empty() {
                anyhow::bail!("page {pgno} does not decrypt; page parameters may be wrong");
            }
            fo.write_all(&plain)?;
        }
    }
    let wal = src.with_file_name(format!("{}-wal", src.file_name().unwrap().to_string_lossy()));
    if wal.exists() {
        apply_wal_with(&tmp, &wal, key, layout)?;
    }
    std::fs::rename(&tmp, dst)?;
    Ok(total)
}

/// Merge WAL (default layout).
pub fn apply_wal(out: &Path, wal: &Path, key: &Key) -> Result<usize> {
    apply_wal_with(out, wal, key, Layout::default())
}

/// Merge WAL: only frames whose salt matches the WAL header (SQLite's own rule).
pub fn apply_wal_with(out: &Path, wal: &Path, key: &Key, layout: Layout) -> Result<usize> {
    let page = layout.page;
    let mut data = Vec::new();
    {
        let mut f = File::open(wal)?;
        f.read_to_end(&mut data)?;
    }
    if data.len() < page {
        return Ok(0);
    }
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if magic != 0x377F_0682 && magic != 0x377F_0683 {
        return Ok(0);
    }
    let page_size = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
    if page_size != page {
        return Ok(0);
    }
    let salt1 = &data[16..20];
    let salt2 = &data[20..24];
    let frame = 24 + page;
    let mut applied = 0usize;
    let mut dbsize: Option<u32> = None;
    let mut f = std::fs::OpenOptions::new().read(true).write(true).open(out)?;
    let mut off = 32usize;
    while off + frame <= data.len() {
        let h = &data[off..off + 24];
        let pgno = u32::from_be_bytes([h[0], h[1], h[2], h[3]]);
        let size = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
        if &h[8..12] != salt1 || &h[12..16] != salt2 || pgno == 0 {
            break;
        }
        let raw = &data[off + 24..off + 24 + page];
        let plain = layout.decrypt_page(raw, key, pgno);
        if plain.is_empty() {
            break;
        }
        f.seek(SeekFrom::Start((pgno as u64 - 1) * page as u64))?;
        f.write_all(&plain)?;
        dbsize = Some(size);
        applied += 1;
        off += frame;
    }
    if let Some(n) = dbsize {
        let want = n as u64 * page as u64;
        if f.metadata()?.len() > want {
            f.set_len(want)?;
        }
    }
    Ok(applied)
}

/// Validate the decrypted output with SQLite itself.
pub fn sqlite_ok(path: &Path) -> bool {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .ok()
    .and_then(|c| {
        c.query_row("pragma quick_check", [], |r| r.get::<_, String>(0))
            .ok()
    })
    .map(|s| s == "ok")
    .unwrap_or(false)
}