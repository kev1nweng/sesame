// SPDX-License-Identifier: AGPL-3.0-or-later
//! Minimal XML helpers.
//!
//! Moments and Favorites store small, regular XML blobs; a full parser is overkill.
//! Three operations only: first `<tag>...</tag>` text, attribute lookup, tag counting.

fn utf8_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else {
        4
    }
}

fn decode_ent(ent: &str) -> Option<char> {
    match ent {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some(' '),
        _ => {
            if let Some(h) = ent.strip_prefix("#x").or_else(|| ent.strip_prefix("#X")) {
                u32::from_str_radix(h, 16).ok().and_then(char::from_u32)
            } else if let Some(d) = ent.strip_prefix('#') {
                d.parse::<u32>().ok().and_then(char::from_u32)
            } else {
                None
            }
        }
    }
}

pub fn unescape(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' {
            if let Some(rel) = s[i..].find(';').filter(|e| *e <= 10) {
                let ent = &s[i + 1..i + rel];
                if let Some(ch) = decode_ent(ent) {
                    out.push(ch);
                    i += rel + 1;
                    continue;
                }
            }
        }
        let n = utf8_len(bytes[i]).min(bytes.len() - i);
        out.push_str(&s[i..i + n]);
        i += n;
    }
    out
}

/// Text inside `<tag>text</tag>` (entities decoded)
pub fn first_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let s = xml.find(&open)? + open.len();
    let e = xml[s..].find(&close)? + s;
    Some(unescape(&xml[s..e]).trim().to_string())
}

pub fn all_text(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(a) = xml[pos..].find(&open) {
        let s = pos + a + open.len();
        let Some(b) = xml[s..].find(&close) else { break };
        let e = s + b;
        out.push(unescape(&xml[s..e]).trim().to_string());
        pos = e + close.len();
    }
    out
}

/// Attribute of a self-closing tag: `<location poiName="Shanghai" .../>`
pub fn attr(xml: &str, tag: &str, name: &str) -> Option<String> {
    let pat = format!("<{tag} ");
    let start = xml.find(&pat)?;
    let end = xml[start..].find('>')? + start;
    let seg = &xml[start..end];
    let key = format!("{name}=\"");
    let ks = seg.find(&key)? + key.len();
    let ke = seg[ks..].find('"')? + ks;
    Some(unescape(&seg[ks..ke]))
}

/// Occurrences of a tag (`<media>` count is the media count)
pub fn count_tag(xml: &str, tag: &str) -> usize {
    xml.matches(&format!("<{tag}")).count()
}

/// First non-empty value, in order
pub fn first_non_empty(cands: Vec<Option<String>>) -> String {
    for c in cands {
        if let Some(v) = c {
            if !v.is_empty() {
                return v;
            }
        }
    }
    String::new()
}