//! Reader for the settings database of dconf (`~/.config/dconf/user`, the GVDB format).
//! Only the value types the checks need are decoded. Every offset is checked, so a damaged
//! or hostile file gives fewer settings, never a crash.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Setting {
    Text(String),
    Flag(bool),
    List(Vec<String>),
    Other,
}

impl Setting {
    pub fn text(&self) -> Option<&str> {
        match self {
            Setting::Text(t) => Some(t),
            _ => None,
        }
    }
}

const SIGNATURE: &[u8] = b"GVariant";
const ITEM: usize = 24;
const LIMIT: usize = 100_000;

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

fn text_of(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes.strip_suffix(&[0]).unwrap_or(bytes)).into_owned()
}

/// A serialised array of strings: the strings, then the end offset of each one.
fn string_list(data: &[u8]) -> Option<Vec<String>> {
    if data.is_empty() {
        return Some(Vec::new());
    }
    let width = if data.len() <= 0xff { 1 } else if data.len() <= 0xffff { 2 } else { 4 };
    let offset = |at: usize| -> Option<usize> {
        let bytes = data.get(at..at.checked_add(width)?)?;
        Some(bytes.iter().rev().fold(0usize, |n, b| (n << 8) | *b as usize))
    };
    let table = offset(data.len().checked_sub(width)?)?;
    let count = data.len().checked_sub(table)? / width;
    let mut start = 0;
    let mut out = Vec::new();
    for i in 0..count.min(LIMIT) {
        let end = offset(table + i * width)?;
        out.push(text_of(data.get(start..end)?));
        start = end;
    }
    Some(out)
}

/// A serialised variant: the value, a zero byte, then its type.
fn decode(variant: &[u8]) -> Setting {
    let Some(split) = variant.iter().rposition(|b| *b == 0) else { return Setting::Other };
    let (data, kind) = (&variant[..split], &variant[split + 1..]);
    match kind {
        b"s" => Setting::Text(text_of(data)),
        b"b" => Setting::Flag(data.first().map(|b| *b != 0).unwrap_or(false)),
        b"as" => string_list(data).map(Setting::List).unwrap_or(Setting::Other),
        _ => Setting::Other,
    }
}

/// Every setting in a database, by its full path ("/org/gnome/…/key"). `None` when the file is
/// not a (little-endian) GVDB file.
pub fn read_database(data: &[u8]) -> Option<BTreeMap<String, Setting>> {
    if !data.starts_with(SIGNATURE) {
        return None;
    }
    let start = u32_at(data, 16)? as usize;
    let end = u32_at(data, 20)? as usize;
    let table = data.get(start..end)?;
    let bloom = (u32_at(table, 0)? & 0x07ff_ffff) as usize;
    let buckets = u32_at(table, 4)? as usize;
    let first = 8usize.checked_add(bloom.checked_mul(4)?)?.checked_add(buckets.checked_mul(4)?)?;
    let items: Vec<&[u8]> = table.get(first..)?.chunks_exact(ITEM).take(LIMIT).collect();
    // an item holds only the last part of its key; its parents hold the rest
    let part = |item: &[u8]| -> Option<String> {
        let at = u32_at(item, 8)? as usize;
        let size = u16::from_le_bytes(item.get(12..14)?.try_into().ok()?) as usize;
        Some(String::from_utf8_lossy(data.get(at..at.checked_add(size)?)?).into_owned())
    };
    let mut out = BTreeMap::new();
    for item in &items {
        if item[14] != b'v' {
            continue;
        }
        let mut key = String::new();
        let mut current: Option<&[u8]> = Some(item);
        // a key has only a few levels; the limit stops loops in damaged files
        for _ in 0..64 {
            let Some(node) = current else { break };
            key.insert_str(0, &part(node)?);
            let parent = u32_at(node, 4)?;
            current = if parent == u32::MAX { None } else { items.get(parent as usize).copied() };
        }
        let from = u32_at(item, 16)? as usize;
        let to = u32_at(item, 20)? as usize;
        if let Some(value) = data.get(from..to) {
            out.insert(key, decode(value));
        }
    }
    Some(out)
}

/// The text key files of a system database (`/etc/dconf/db/local.d/*`).
pub fn read_keyfile(text: &str) -> BTreeMap<String, Setting> {
    let unquote = |v: &str| v.trim().trim_start_matches(['\'', '"']).trim_end_matches(['\'', '"']).to_string();
    let mut folder = String::new();
    let mut out = BTreeMap::new();
    for line in text.lines().map(str::trim).filter(|l| !l.starts_with('#')) {
        if let Some(name) = line.strip_prefix('[') {
            folder = format!("/{}/", name.trim_end_matches(']').trim_matches('/'));
        } else if let Some((key, value)) = line.split_once('=') {
            let value = value.trim();
            let setting = match value {
                "true" => Setting::Flag(true),
                "false" => Setting::Flag(false),
                _ => match value.strip_prefix('[') {
                    Some(list) => Setting::List(list.trim_end_matches(']').split(',').map(unquote).filter(|v| !v.is_empty()).collect()),
                    None => Setting::Text(unquote(value)),
                },
            };
            out.insert(format!("{folder}{}", key.trim()), setting);
        }
    }
    out
}
