// SPDX-License-Identifier: AGPL-3.0-or-later
//! Moments (sns.db) export.
//!
//! SnsTimeLine.content is an `<SnsDataItem><TimelineObject>...` XML blob:
//! text in `<contentDesc>`, media in `<mediaList>`, location in `<location>`,
//! author name in `<LocalExtraInfo><nickname>`.
//! Comments live in `SnsMessage_tmp3` (type=2), joined to posts via feed_id = tid.

use anyhow::Result;
use rusqlite::{Connection, OpenFlags};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::Path;

use crate::util::fmt_time;
use crate::xml;

struct Comment {
    ts: i64,
    who: String,
    text: String,
}

struct Post {
    ts: i64,
    author: String,
    text: String,
    media: usize,
    video: bool,
    place: String,
    comments: Vec<Comment>,
    likes: Vec<String>,
}

pub fn run(dec_root: &Path, out: &Path) -> Result<()> {
    let db = dec_root.join("sns").join("sns.db");
    anyhow::ensure!(
        db.exists(),
        "decrypted sns.db not found ({}). Run `sesame decrypt` first",
        db.display()
    );
    let con = Connection::open_with_flags(&db, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

    // comments: feed_id -> list (type=2); likes: feed_id -> names (type=1)
    let mut comments: HashMap<i64, Vec<Comment>> = HashMap::new();
    if let Ok(mut stmt) = con.prepare(
        "select feed_id, create_time, from_nickname, content from SnsMessage_tmp3 where type=2",
    ) {
        if let Ok(rows) = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0).unwrap_or(0),
                r.get::<_, i64>(1).unwrap_or(0),
                r.get::<_, String>(2).unwrap_or_default(),
                r.get::<_, String>(3).unwrap_or_default(),
            ))
        }) {
            for (feed, ts, who, text) in rows.flatten() {
                comments.entry(feed).or_default().push(Comment { ts, who, text });
            }
        }
    }

    let mut likes: HashMap<i64, Vec<String>> = HashMap::new();
    if let Ok(mut stmt) = con.prepare(
        "select feed_id, from_nickname from SnsMessage_tmp3 where type=1 order by create_time",
    ) {
        if let Ok(rows) = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0).unwrap_or(0),
                r.get::<_, String>(1).unwrap_or_default(),
            ))
        }) {
            for (feed, who) in rows.flatten() {
                if !who.is_empty() {
                    likes.entry(feed).or_default().push(who);
                }
            }
        }
    }

    // timeline
    let mut posts: Vec<Post> = Vec::new();
    let mut stmt = con.prepare("select tid, user_name, content from SnsTimeLine")?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0).unwrap_or(0),
            r.get::<_, String>(1).unwrap_or_default(),
            r.get::<_, String>(2).unwrap_or_default(),
        ))
    })?;
    for (tid, uname, raw) in rows.flatten() {
        if raw.trim().is_empty() {
            continue;
        }
        let ts = xml::first_text(&raw, "createTime")
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        let text = xml::first_text(&raw, "contentDesc").unwrap_or_default();
        let author = xml::first_text(&raw, "nickname")
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| uname.clone());
        let media = xml::count_tag(&raw, "media");
        let video = xml::first_text(&raw, "videoDuration")
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0)
            > 0;
        let place = xml::attr(&raw, "location", "poiName").unwrap_or_default();
        let mut cs = comments.remove(&tid).unwrap_or_default();
        cs.sort_by_key(|c| c.ts);
        let lk = likes.remove(&tid).unwrap_or_default();
        posts.push(Post { ts, author, text, media, video, place, comments: cs, likes: lk });
    }
    posts.sort_by_key(|p| p.ts);

    std::fs::create_dir_all(out)?;
    let mut md = String::new();
    let years = posts.iter().filter(|p| p.ts > 0).count();
    let with_text = posts.iter().filter(|p| !p.text.is_empty()).count();
    let _ = writeln!(md, "# Moments export\n");
    let _ = writeln!(
        md,
        "{} posts ({} with text, {} with interactions), {} ~ {}\n",
        posts.len(),
        with_text,
        posts.iter().filter(|p| !p.comments.is_empty() || !p.likes.is_empty()).count(),
        posts.first().map(|p| fmt_time(p.ts)).unwrap_or_default(),
        posts.last().map(|p| fmt_time(p.ts)).unwrap_or_default()
    );
    if years == 0 {
        let _ = writeln!(md, "(no valid timestamps parsed; the schema may have changed)");
    }

    let mut csv = String::from("time,author,text,media,place,likes,comments\n");
    let mut cur_year = i32::MIN;
    for p in &posts {
        let t = fmt_time(p.ts);
        let year: i32 = t.get(0..4).and_then(|y| y.parse().ok()).unwrap_or(0);
        if year != cur_year {
            cur_year = year;
            let _ = writeln!(md, "\n## {year}\n");
        }
        let _ = writeln!(md, "### {t} · {}", p.author);
        if !p.text.is_empty() {
            let _ = writeln!(md, "\n{}\n", p.text);
        }
        let mut marks: Vec<String> = Vec::new();
        if p.video {
            marks.push("🎬 video".into());
        } else if p.media > 0 {
            marks.push(format!("🖼 images x{}", p.media));
        }
        if !p.place.is_empty() {
            marks.push(format!("📍 {}", p.place));
        }
        if !marks.is_empty() {
            let _ = writeln!(md, "{}\n", marks.join("　"));
        }
        if !p.likes.is_empty() {
            let _ = writeln!(md, "❤️ likes: {}\n", p.likes.join(", "));
        }
        if !p.comments.is_empty() {
            let _ = writeln!(md, "**comments**");
            for c in &p.comments {
                let _ = writeln!(md, "- {} ({}): {}", c.who, fmt_time(c.ts), c.text);
            }
            let _ = writeln!(md);
        }
        let _ = writeln!(
            csv,
            "{},{},{},{},{},{},{}\n",
            t,
            csv_esc(&p.author),
            csv_esc(&p.text.replace('\n', " ")),
            p.media,
            csv_esc(&p.place),
            p.likes.len(),
            p.comments.len()
        );
    }

    std::fs::write(out.join("moments.md"), md)?;
    std::fs::write(out.join("moments.csv"), csv)?;
    println!(
        "moments: {} posts, {} likes, {} comments -> {}/moments.md",
        posts.len(),
        posts.iter().map(|p| p.likes.len()).sum::<usize>(),
        posts.iter().map(|p| p.comments.len()).sum::<usize>(),
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