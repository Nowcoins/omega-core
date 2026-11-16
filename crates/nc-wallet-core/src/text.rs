//! Text a site or a transaction hands the wallet, made safe to show.
//!
//! A message to sign, a memo, a seed string: all of it is chosen by someone
//! else, and Unicode has characters that change what a reader sees without
//! being seen themselves. A right-to-left override (U+202E) reverses the text
//! after it, a zero-width space splits a word so that two different strings
//! look the same, a tag character carries a message no one can read, and a line
//! or paragraph separator starts a "new line" that a line-based screen does not
//! draw. [`inspect`] finds them. A text that holds any is **not** reported as
//! plain text (`text` is `None`); a visibly escaped rendering (`escaped`) is
//! always given for text that is UTF-8, so a screen can show what is there.

/// Whether `c` is a character that is not drawn or that changes how the
/// text around it is drawn: the Unicode format characters (category Cf), the
/// line and paragraph separators (Zl, Zp), the blank-looking Hangul fillers
/// and the variation selectors supplement.
///
/// The standard library has no general-category tables, so the Cf ranges are
/// written out (Unicode 16). Anything a later version adds to Cf is not caught
/// here; the list is the one place to add it.
#[must_use]
pub fn is_hidden(c: char) -> bool {
    matches!(
        u32::from(c),
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x115F..=0x1160
            | 0x180E
            | 0x200B..=0x200F
            | 0x2028..=0x202E
            | 0x2060..=0x206F
            | 0x3164
            | 0xFEFF
            | 0xFFA0
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
            | 0xE0100..=0xE01EF
    )
}

/// Whether `c` is a control character that a reader cannot take for text:
/// every Cc but newline, carriage return and tab.
#[must_use]
pub fn is_odd_control(c: char) -> bool {
    c.is_control() && !matches!(c, '\n' | '\r' | '\t')
}

/// What was found in a piece of bytes that may be text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspected {
    /// The text itself, only if the bytes are UTF-8 with no hidden character
    /// and no control character but newline, carriage return and tab. This is
    /// the one to show as the message.
    pub text: Option<String>,
    /// The text with each hidden or control character written as `<U+202E>`;
    /// `Some` for any UTF-8, `None` otherwise. Safe to show, whatever the text.
    pub escaped: Option<String>,
    /// The number of characters (0 if not UTF-8). The screen can warn when it
    /// shows less than this.
    pub chars: usize,
    /// How many hidden characters there are.
    pub hidden: usize,
    /// How many control characters there are (not counting newline, carriage
    /// return and tab).
    pub control: usize,
}

impl Inspected {
    /// Whether the bytes are UTF-8 text with a hidden or control character.
    #[must_use]
    pub const fn has_hidden_or_control(&self) -> bool {
        self.hidden > 0 || self.control > 0
    }
}

/// Reads `bytes` as text, finding what a screen must not show as it is.
#[must_use]
pub fn inspect(bytes: &[u8]) -> Inspected {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Inspected { text: None, escaped: None, chars: 0, hidden: 0, control: 0 };
    };
    let (escaped, hidden, control) = escape_counting(text);
    Inspected {
        text: (hidden == 0 && control == 0).then(|| text.to_owned()),
        escaped: Some(escaped),
        chars: text.chars().count(),
        hidden,
        control,
    }
}

fn escape_counting(text: &str) -> (String, usize, usize) {
    use std::fmt::Write as _;
    let (mut hidden, mut control) = (0, 0);
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if is_hidden(c) {
            hidden += 1;
        } else if is_odd_control(c) {
            control += 1;
        } else {
            out.push(c);
            continue;
        }
        let _ = write!(out, "<U+{:04X}>", u32::from(c));
    }
    (out, hidden, control)
}

/// `text` with every hidden or control character written visibly, and
/// newlines, carriage returns and tabs turned into spaces: for a one-line field
/// (a memo, a seed) taken from a transaction.
#[must_use]
pub fn one_line(text: &str) -> String {
    let flat: String =
        text.chars().map(|c| if matches!(c, '\n' | '\r' | '\t') { ' ' } else { c }).collect();
    escape_counting(&flat).0
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_text() {
        let found = inspect("Sign in\n\tfine ✓ 日本語".as_bytes());
        assert_eq!(found.text.as_deref(), Some("Sign in\n\tfine ✓ 日本語"));
        assert_eq!(found.hidden + found.control, 0);
        assert_eq!(found.chars, 19);
    }

    #[test]
    fn a_right_to_left_override_is_not_plain_text() {
        let found = inspect("pay \u{202E}0.1 ETH\u{202C}".as_bytes());
        assert_eq!(found.text, None);
        assert_eq!(found.hidden, 2);
        assert_eq!(found.escaped.as_deref(), Some("pay <U+202E>0.1 ETH<U+202C>"));
    }

    #[test]
    fn zero_width_separators_and_tags_are_hidden() {
        for c in
            ['\u{200B}', '\u{200D}', '\u{2028}', '\u{2029}', '\u{FEFF}', '\u{E0041}', '\u{2066}']
        {
            let found = inspect(format!("a{c}b").as_bytes());
            assert_eq!(found.text, None, "{:X}", u32::from(c));
            assert_eq!(found.hidden, 1);
        }
    }

    #[test]
    fn control_characters_and_bad_utf8_are_unreadable() {
        let found = inspect(b"a\x00b");
        assert_eq!((found.text, found.control), (None, 1));
        assert_eq!(found.escaped.as_deref(), Some("a<U+0000>b"));
        let found = inspect(&[0xff, 0xfe]);
        assert_eq!((found.text, found.escaped), (None, None));
    }

    #[test]
    fn a_one_line_field_has_no_line_breaks_or_hidden_characters() {
        assert_eq!(one_line("a\nb\u{200B}"), "a b<U+200B>");
    }
}
