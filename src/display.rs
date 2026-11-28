//! Text from the system, made safe to show.
//!
//! Whoever creates a file or a process chooses its name, and a name may hold escape sequences
//! that move the terminal's cursor and erase a finding, end the terminal's protection of pasted
//! text, or turn the writing direction so a name reads as another one. Everything shown to a
//! person, or copied by them, has such characters written out as escapes, such as `\x1b`.

use std::fmt::Write as _;

/// A character that is not seen for what it is: control characters, and the ones that change
/// the direction of text, break lines or take no room.
pub fn is_hidden(c: char) -> bool {
    c.is_control() || matches!(c, '\u{061c}' | '\u{200b}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
}

fn write_out(out: &mut String, c: char) {
    match c {
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        c if u32::from(c) <= 0xff => {
            let _ = write!(out, "\\x{:02x}", u32::from(c));
        }
        c => {
            let _ = write!(out, "\\u{:04x}", u32::from(c));
        }
    }
}

fn replace(text: &str, keep: &[char]) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if is_hidden(c) && !keep.contains(&c) {
            write_out(&mut out, c);
        } else {
            out.push(c);
        }
    }
    out
}

/// Text of several lines (evidence, notes): line breaks and tabs stay.
pub fn text(s: &str) -> String {
    replace(&s.replace("\r\n", "\n"), &['\n', '\t'])
}

/// Text that must stay on one line (a title, a command to copy, a table cell).
pub fn line(s: &str) -> String {
    replace(s, &[])
}

/// JSON as `serde_json` writes it, with the remaining hidden characters as `\u….` escapes: the
/// same data, and safe to `cat`. (Only strings can hold them; the line breaks between values
/// stay.)
pub fn json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c != '\n' && is_hidden(c) {
            let _ = write!(out, "\\u{:04x}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}
