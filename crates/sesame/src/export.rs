// SPDX-License-Identifier: AGPL-3.0-or-later
//! Export decrypted databases as readable chat history (txt / csv / html).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Result;
use md5::{Digest, Md5};
use rusqlite::{Connection, OpenFlags};

use crate::util::fmt_time;

struct Line {
    ts: String,
    sender: String,
    text: String,
}

struct Chat {
    username: String,
    display: String,
    kind: &'static str,
    lines: Vec<Line>,
}

fn open_ro(path: &Path) -> Option<Connection> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()
}

fn columns(con: &Connection, table: &str) -> Vec<String> {
    let sql = format!("pragma table_info('{}')", table.replace('\'', "''"));
    let mut out = Vec::new();
    if let Ok(mut stmt) = con.prepare(&sql) {
        if let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(1)) {
            for r in rows.flatten() {
                out.push(r);
            }
        }
    }
    out
}

fn md5_hex(s: &str) -> String {
    let mut h = Md5::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn chat_kind(username: &str) -> &'static str {
    if username.ends_with("@chatroom") {
        "group"
    } else if username.starts_with("gh_") {
        "official account"
    } else if username.ends_with("@openim") {
        "WeCom"
    } else if username.starts_with("wxid_") {
        "direct"
    } else {
        "other"
    }
}

fn load_names(dec_root: &Path) -> HashMap<String, String> {
    let mut names = HashMap::new();
    let path = dec_root.join("contact/contact.db");
    let Some(con) = open_ro(&path) else {
        return names;
    };
    let cols = columns(&con, "contact");
    if cols.is_empty() {
        return names;
    }
    let pick = |c: &str| cols.iter().any(|x| x == c);
    let expr = format!(
        "select username, {} from contact",
        if pick("remark") && pick("nick_name") {
            "coalesce(nullif(remark,''), nullif(nick_name,''), username)"
        } else if pick("nick_name") {
            "coalesce(nullif(nick_name,''), username)"
        } else {
            "username"
        }
    );
    if let Ok(mut stmt) = con.prepare(&expr) {
        if let Ok(rows) = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        }) {
            for (u, n) in rows.flatten() {
                names.insert(u, n);
            }
        }
    }
    names
}

fn load_sessions(dec_root: &Path) -> HashSet<String> {
    let mut set = HashSet::new();
    let Some(con) = open_ro(&dec_root.join("session/session.db")) else {
        return set;
    };
    if let Ok(mut stmt) = con.prepare("select username from SessionTable") {
        if let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) {
            for u in rows.flatten() {
                set.insert(u);
            }
        }
    }
    set
}

fn gunzip(value: &[u8], ct: i64) -> String {
    if ct == 4 {
        if let Ok(v) = zstd::stream::decode_all(value) {
            return String::from_utf8_lossy(&v).to_string();
        }
    }
    String::from_utf8_lossy(value).to_string()
}

/// Group messages look like `wxid_xxx:\nbody`; split author from body.
fn split_group_prefix(s: &str) -> Option<(String, String)> {
    let mut seen = 0;
    for (i, ch) in s.char_indices() {
        if i > 64 {
            return None;
        }
        if ch == ':' {
            if s[i + 1..].starts_with('\n') {
                let head = &s[..i];
                if head.len() >= 3
                    && head
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "_-@.".contains(c))
                {
                    return Some((head.to_string(), s[i + 2..].to_string()));
                }
            }
            return None;
        }
        seen += 1;
        let _ = seen;
    }
    None
}

const APP_LABEL: &[(i64, &str)] = &[
    (3, "[music]"),
    (5, "[link]"),
    (6, "[file]"),
    (19, "[chat log]"),
    (33, "[mini program]"),
    (36, "[mini program]"),
    (51, "[channel]"),
    (57, "[quote]"),
    (63, "[live]"),
    (87, "[group announcement]"),
    (2000, "[transfer]"),
    (2001, "[red packet]"),
];

fn tag_value<'a>(raw: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = raw.find(&open)? + open.len();
    let end = raw[start..].find(&close)? + start;
    Some(raw[start..end].trim())
}

fn format_body(base: i64, sub: i64, raw: &str) -> String {
    let raw = raw.trim();
    match base {
        3 => "[image]".into(),
        34 => match tag_value(raw, "voicelength").and_then(|v| v.parse::<i64>().ok()) {
            Some(ms) => format!("[voice {}s]", (ms as f64 / 1000.0).round() as i64),
            None => "[voice]".into(),
        },
        43 => "[video]".into(),
        47 => "[sticker]".into(),
        48 => "[location]".into(),
        42 => "[contact card]".into(),
        50 => "[voice call]".into(),
        49 => {
            let kind = tag_value(raw, "type")
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(sub);
            let label = APP_LABEL
                .iter()
                .find(|(k, _)| *k == kind)
                .map(|(_, v)| *v)
                .unwrap_or("[app message]");
            let title = tag_value(raw, "title")
                .map(|t| t.trim_start_matches("<![CDATA[").trim_end_matches("]]>").to_string())
                .unwrap_or_default();
            let title = if title.chars().count() > 120 {
                let t: String = title.chars().take(120).collect();
                format!("{t}…")
            } else {
                title
            };
            format!("{label} {title}").trim().to_string()
        }
        _ => {
            // unknown type: plain text passes through, tagged payloads are suppressed
            if !raw.is_empty() && !raw.starts_with('<') {
                raw.to_string()
            } else {
                format!("[unknown type {base}]")
            }
        }
    }
}

fn export_table(con: &Connection, table: &str, username: &str, names: &HashMap<String, String>, me: &str) -> Vec<Line> {
    let cols = columns(con, table);
    let has_ct = cols.iter().any(|c| c == "WCDB_CT_message_content");
    let sql = format!(
        "select local_type, create_time, real_sender_id, message_content, {} from '{}' order by create_time, local_id",
        if has_ct { "WCDB_CT_message_content" } else { "0" },
        table.replace('\'', "''")
    );
    let mut id2name: HashMap<i64, String> = HashMap::new();
    if let Ok(mut stmt) = con.prepare("select rowid, user_name from Name2Id") {
        if let Ok(rows) = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))) {
            for (id, u) in rows.flatten() {
                id2name.insert(id, u);
            }
        }
    }

    let mut out = Vec::new();
    let Ok(mut stmt) = con.prepare(&sql) else {
        return out;
    };
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, Option<i64>>(2)?.unwrap_or(0),
            r.get::<_, Option<rusqlite::types::Value>>(3)?,
            r.get::<_, Option<i64>>(4)?.unwrap_or(0),
        ))
    });
    let Ok(rows) = rows else { return out };

    for row in rows {
        let Ok((mtype, ts, sender_id, content, ct)) = row else {
            continue;
        };
        // the column may be BLOB (zstd) or TEXT (plain)
        let raw_bytes = match content {
            Some(rusqlite::types::Value::Blob(b)) => b,
            Some(rusqlite::types::Value::Text(t)) => t.into_bytes(),
            _ => Vec::new(),
        };
        let base = mtype & 0xFFFF_FFFF;
        let sub = mtype >> 32;
        if base == 10000 || base == 10002 || base == 10003 {
            continue;
        }
        let raw = gunzip(&raw_bytes, ct);
        let (author, body) = match split_group_prefix(raw.trim()) {
            Some((a, b)) => (Some(a), b),
            None => (None, raw.clone()),
        };
        let text = format_body(base, sub, if author.is_some() { &body } else { &raw });
        if text.trim().is_empty() {
            continue;
        }
        let sender = if username.ends_with("@chatroom") {
            author
                .as_ref()
                .map(|a| names.get(a).cloned().unwrap_or_else(|| a.clone()))
                .unwrap_or_else(|| "me".into())
        } else {
            let sid = id2name.get(&sender_id).cloned().unwrap_or_default();
            if sid == me {
                "me".to_string()
            } else {
                names.get(&sid).cloned().unwrap_or(sid)
            }
        };
        out.push(Line {
            ts: fmt_time(ts),
            sender,
            text,
        });
    }
    out
}

/// Container directory looks like `wxid_abc123_5c83`; the real id is `wxid_abc123`.
fn account_wxid(raw: &str) -> String {
    if let Some(idx) = raw.rfind('_') {
        let (head, tail) = raw.split_at(idx);
        let suffix = &tail[1..];
        if head.starts_with("wxid_")
            && suffix.len() == 4
            && suffix.chars().all(|c| c.is_ascii_hexdigit())
        {
            return head.to_string();
        }
    }
    raw.to_string()
}

fn safe_name(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        if ch.is_alphanumeric() || "_-@.@".contains(ch) {
            out.push(ch);
        } else {
            out.push('_');
        }
        if out.chars().count() >= 60 {
            break;
        }
    }
    if out.is_empty() {
        "chat".into()
    } else {
        out
    }
}

pub fn run(dec_root: &Path, out: &Path, min_messages: usize) -> Result<()> {
    std::fs::create_dir_all(out.join("text"))?;
    let names = load_names(dec_root);
    let sessions = load_sessions(dec_root);
    println!("contacts: {}, conversations: {}", names.len(), sessions.len());

    let mut by_md5: HashMap<String, String> = sessions.iter().map(|u| (md5_hex(u), u.clone())).collect();
    let mut all_names = names.clone();
    for u in &sessions {
        all_names.entry(u.clone()).or_insert_with(|| u.clone());
    }

    let me = account_wxid(&crate::wechat::detect().wxid.unwrap_or_default());

    let mut chats: BTreeMap<String, Chat> = BTreeMap::new();
    let msg_dir = dec_root.join("message");
    let mut dbs: Vec<PathBuf> = std::fs::read_dir(&msg_dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| {
                    let n = p.file_name().unwrap_or_default().to_string_lossy();
                    // message_0/1 are regular chats; biz_message_0 is official accounts
                    (n.starts_with("message_") || n.starts_with("biz_message_"))
                        && n.ends_with(".db")
                        && !n.contains("fts")
                })
                .collect()
        })
        .unwrap_or_default();
    dbs.sort();

    for db in dbs {
        let Some(con) = open_ro(&db) else { continue };
        if let Ok(mut stmt) = con.prepare("select rowid, user_name from Name2Id") {
            if let Ok(rows) = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))) {
                for (_id, u) in rows.flatten() {
                    all_names.entry(u.clone()).or_insert_with(|| u.clone());
                    by_md5.entry(md5_hex(&u)).or_insert(u);
                }
            }
        }
        let mut tables: Vec<String> = Vec::new();
        if let Ok(mut stmt) = con.prepare("select name from sqlite_master where type='table' and name like 'Msg_%'") {
            if let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) {
                for t in rows.flatten() {
                    tables.push(t);
                }
            }
        }
        for t in tables {
            let hash = &t[4..];
            let Some(username) = by_md5.get(hash).cloned() else { continue };
            let lines = export_table(&con, &t, &username, &all_names, &me);
            if lines.len() < min_messages {
                continue;
            }
            let display = all_names.get(&username).cloned().unwrap_or_else(|| username.clone());
            let entry = chats.entry(username.clone()).or_insert_with(|| Chat {
                username: username.clone(),
                display,
                kind: chat_kind(&username),
                lines: Vec::new(),
            });
            if lines.len() > entry.lines.len() {
                entry.lines = lines;
            }
        }
    }

    let mut index: Vec<(String, String, &'static str, usize, String, String, String)> = Vec::new();
    for (username, chat) in &chats {
        let fname = format!("{}__{}.txt", safe_name(&chat.display), &md5_hex(username)[..8]);
        let path = out.join("text").join(&fname);
        let mut s = String::new();
        let _ = writeln!(s, "# {}  ({})  {} messages", chat.display, chat.kind, chat.lines.len());
        if let (Some(first), Some(last)) = (chat.lines.first(), chat.lines.last()) {
            let _ = writeln!(s, "# {} ~ {}\n", first.ts, last.ts);
        }
        for l in &chat.lines {
            let _ = writeln!(s, "[{}] {}: {}", l.ts, l.sender, l.text);
        }
        std::fs::write(&path, s)?;
        let (start, end) = match (chat.lines.first(), chat.lines.last()) {
            (Some(f), Some(l)) => (f.ts.clone(), l.ts.clone()),
            _ => (String::new(), String::new()),
        };
        index.push((
            chat.display.clone(),
            username.clone(),
            chat.kind,
            chat.lines.len(),
            start,
            end,
            format!("text/{fname}"),
        ));
    }
    index.sort_by(|a, b| b.5.cmp(&a.5));

    let mut csv = String::from("name,username,type,count,start,end,file\n");
    for r in &index {
        let _ = writeln!(
            csv,
            "\"{}\",\"{}\",\"{}\",{},\"{}\",\"{}\",\"{}\"",
            r.0.replace('"', "\"\""),
            r.1,
            r.2,
            r.3,
            r.4,
            r.5,
            r.6
        );
    }
    std::fs::write(out.join("index.csv"), csv)?;

    let mut html = String::from(
        "<!doctype html><meta charset='utf-8'><title>WeChat chat history</title>\
         <style>body{font:14px/1.6 -apple-system,sans-serif;margin:32px}\
         table{border-collapse:collapse}td,th{padding:6px 12px;border-bottom:1px solid #eee;\
         text-align:left}a{color:#07c;text-decoration:none}</style>",
    );
    let total: usize = index.iter().map(|r| r.3).sum();
    let _ = write!(
        html,
        "<h2>WeChat chat history</h2><p>{} conversations, {} messages</p><table>\
         <tr><th>conversation</th><th>type</th><th>messages</th><th>first</th><th>last</th></tr>",
        index.len(),
        total
    );
    for r in &index {
        let _ = writeln!(
            html,
            "<tr><td><a href='{}'>{}</a></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            r.6, r.0, r.2, r.3, r.4, r.5
        );
    }
    html.push_str("</table>");
    std::fs::write(out.join("index.html"), html)?;

    println!(
        "done: {} conversations, {} messages -> {}",
        index.len(),
        total,
        out.join("index.html").display()
    );
    Ok(())
}