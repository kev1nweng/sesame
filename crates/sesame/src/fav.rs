// SPDX-License-Identifier: AGPL-3.0-or-later
//! Favorites (favorite.db) export.
//!
//! fav_db_item.content is a `<favitem type="N">...` blob whose children vary by type:
//! 1 text in `<desc>`, 5 links in `<weburlitem>`, 8 files in `<title>`,
//! 32 music in `<pagetitle>`+`<mvSingerName>`, 20 channels in `<title>`+`<nickname>`.
//! Rather than hardcoding each type, three candidate groups (title/description/link) are
//! tried in order, so unknown types still produce something readable.

use anyhow::Result;
use rusqlite::{Connection, OpenFlags};
use std::fmt::Write as _;
use std::path::Path;

use crate::util::fmt_time;
use crate::xml;

fn type_name(t: i64) -> &'static str {
    match t {
        1 => "text",
        2 => "image",
        3 => "video",
        4 => "short video",
        5 => "link",
        8 => "file",
        14 => "chat log",
        18 => "voice",
        20 => "channel",
        32 => "music",
        _ => "other",
    }
}

pub fn run(dec_root: &Path, out: &Path) -> Result<()> {
    let db = dec_root.join("favorite").join("favorite.db");
    anyhow::ensure!(
        db.exists(),
        "decrypted favorite.db not found ({}). Run `sesame decrypt` first",
        db.display()
    );
    let con = Connection::open_with_flags(&db, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

    struct Item {
        ty: i64,
        ts: i64,
        title: String,
        desc: String,
        link: String,
        from: String,
    }

    let mut items: Vec<Item> = Vec::new();
    let mut stmt = con.prepare("select type, update_time, content from fav_db_item")?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0).unwrap_or(0),
            r.get::<_, i64>(1).unwrap_or(0),
            r.get::<_, String>(2).unwrap_or_default(),
        ))
    })?;
    for (ty, ts, raw) in rows.flatten() {
        if raw.trim().is_empty() {
            continue;
        }
        // prefer the XML createtime over the row's update_time
        let created = xml::first_text(&raw, "createtime")
            .and_then(|s| s.parse::<i64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(ts);
        let title = xml::first_non_empty(vec![
            xml::first_text(&raw, "pagetitle"),
            xml::first_text(&raw, "datatitle"),
            xml::first_text(&raw, "title"),
        ]);
        let desc = xml::first_non_empty(vec![
            xml::first_text(&raw, "pagedesc"),
            xml::first_text(&raw, "datadesc"),
            xml::first_text(&raw, "desc"),
        ]);
        let link = xml::first_non_empty(vec![
            xml::first_text(&raw, "link"),
            xml::first_text(&raw, "stream_weburl"),
            xml::first_text(&raw, "url"),
        ]);
        let from = xml::first_non_empty(vec![
            xml::first_text(&raw, "realchatname"),
            xml::first_text(&raw, "fromusr"),
            xml::first_text(&raw, "nickname"),
        ]);
        items.push(Item { ty, ts: created, title, desc, link, from });
    }
    items.sort_by_key(|i| std::cmp::Reverse(i.ts));

    std::fs::create_dir_all(out)?;
    let mut md = String::new();
    let _ = writeln!(md, "# Favorites export\n");
    let _ = writeln!(
        md,
        "{} items, {} ~ {}\n",
        items.len(),
        items.last().map(|i| fmt_time(i.ts)).unwrap_or_default(),
        items.first().map(|i| fmt_time(i.ts)).unwrap_or_default()
    );

    let mut csv = String::from("type,time,title,description,link,source\n");
    for (n, it) in items.iter().enumerate() {
        let _ = writeln!(md, "## {}. {} · {}", n + 1, type_name(it.ty), fmt_time(it.ts));
        if !it.title.is_empty() {
            let _ = writeln!(md, "\n**{}**", it.title);
        }
        if !it.desc.is_empty() {
            let _ = writeln!(md, "\n{}", it.desc);
        }
        if !it.link.is_empty() {
            let _ = writeln!(md, "\n<{}>", it.link);
        }
        if !it.from.is_empty() {
            let _ = writeln!(md, "\nsource: {}", it.from);
        }
        let _ = writeln!(md);
        let _ = writeln!(
            csv,
            "{},{},{},{},{},{}\n",
            type_name(it.ty),
            fmt_time(it.ts),
            csv_esc(&it.title),
            csv_esc(&it.desc.replace('\n', " ")),
            csv_esc(&it.link),
            csv_esc(&it.from)
        );
    }

    std::fs::write(out.join("favorites.md"), md)?;
    std::fs::write(out.join("favorites.csv"), csv)?;
    println!(
        "favorites: {} items -> {}/favorites.md",
        items.len(),
        out.display()
    );
    Ok(())
}

fn csv_esc(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}