//! The text of a message a site asks to be signed (`personal_sign`, Solana's
//! `signMessage`): what is shown, what is hidden in it, and, when it is a
//! Sign-In with Ethereum / Solana message (EIP-4361), the fields it claims.
//!
//! A site writes the message, so everything in it is a claim. The wallet shows
//! the claimed domain next to the origin the request really came from, and says
//! when they differ (`siwe_domain_mismatch`): a phishing page can ask for a
//! sign-in "to a bank" that the bank's site will accept.

use nc_wallet_core::text;
use serde_json::{Value, json};

use super::SigningError;
use super::json::{Obj, bad};
use super::warning::{self, Code};

/// The longest origin a request may name.
const MAX_ORIGIN: usize = 2048;

/// The request's optional `origin`: where the request came from (`https://example.com`,
/// as the browser names it). The engine compares it with the domain of a sign-in message.
pub(super) fn map_origin(map: &Obj) -> Result<Option<&str>, SigningError> {
    match map.get("origin") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(origin)) if origin.len() <= MAX_ORIGIN => Ok(Some(origin)),
        Some(_) => Err(bad("origin is a short text")),
    }
}

/// The `details` of a message summary.
///
/// * `message_len`: the whole message in bytes, and `text_chars` in characters: a screen that
///   shows less than this must say so.
/// * `text`: the message, only if it is UTF-8 with no hidden or control character. `null`
///   means: do not show it as it is. `text_escaped` is then still the text with each
///   hidden character written as `<U+202E>`, safe to show.
/// * `hidden_characters`: how many bidi, zero-width, separator, tag or control characters.
/// * `siwe`: the sign-in message's fields, or `null`.
/// * `origin`: where the request came from, if the request said.
pub(super) fn message_details(
    bytes: &[u8],
    chain: &str,
    signer: &str,
    origin: Option<&str>,
) -> Value {
    let found = text::inspect(bytes);
    let siwe = found.text.as_deref().and_then(|t| parse_siwe(t, chain)).map(|s| {
        let mut value = s.to_value();
        value["domain_matches_origin"] = json!(origin.map(|o| domain_matches(&s, o)));
        value["address_matches_signer"] = json!(if chain == "Ethereum" {
            s.address.eq_ignore_ascii_case(signer)
        } else {
            s.address == signer
        });
        value
    });
    json!({
        "message_len": bytes.len(),
        "text_chars": found.chars,
        "text": found.text,
        "text_escaped": found.escaped,
        "hidden_characters": found.hidden + found.control,
        "looks_like_sign_in": found
            .text
            .as_deref()
            .is_some_and(|t| t.contains("wants you to sign in with your")),
        "siwe": siwe,
        "origin": origin,
    })
}

/// The warnings a message's details raise.
pub(super) fn message_warnings(details: &Value) -> Vec<Code> {
    let mut warnings = Vec::new();
    if details["text"].is_null() {
        warnings.push(warning::UNREADABLE_MESSAGE);
    }
    if details["hidden_characters"].as_u64().unwrap_or(0) > 0 {
        warnings.push(warning::HIDDEN_CHARACTERS);
    }
    match &details["siwe"] {
        Value::Null => {
            if details["looks_like_sign_in"] == json!(true) {
                warnings.push(warning::SIWE_MALFORMED);
            }
        }
        siwe => {
            if siwe["domain_matches_origin"] == json!(false) {
                warnings.push(warning::SIWE_DOMAIN_MISMATCH);
            }
            if siwe["address_matches_signer"] == json!(false) {
                warnings.push(warning::SIWE_ADDRESS_MISMATCH);
            }
        }
    }
    warnings
}

/// An EIP-4361 message, as it says of itself.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Siwe {
    scheme: Option<String>,
    /// The domain the message says is asking (`example.com` or `example.com:8080`).
    pub(super) domain: String,
    pub(super) address: String,
    statement: Option<String>,
    uri: String,
    version: String,
    chain_id: String,
    nonce: String,
    issued_at: String,
    expiration_time: Option<String>,
    not_before: Option<String>,
    request_id: Option<String>,
    resources: Vec<String>,
}

impl Siwe {
    fn to_value(&self) -> Value {
        json!({
            "scheme": self.scheme,
            "claimed_domain": self.domain,
            "address": self.address,
            "statement": self.statement,
            "uri": self.uri,
            "version": self.version,
            "chain_id": self.chain_id,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "expiration_time": self.expiration_time,
            "not_before": self.not_before,
            "request_id": self.request_id,
            "resources": self.resources,
        })
    }
}

/// Reads an EIP-4361 message (`chain` is `Ethereum`, or `Solana` for the same
/// layout). Strict about the layout: anything that departs from it is not parsed
/// (the caller warns that it looks like a sign-in message that is not well formed).
pub(super) fn parse_siwe(text: &str, chain: &str) -> Option<Siwe> {
    let mut lines = text.split('\n');
    let header = lines.next()?;
    let who = header.strip_suffix(&format!(" wants you to sign in with your {chain} account:"))?;
    let (scheme, domain) = match who.split_once("://") {
        Some((scheme, domain)) => (Some(scheme.to_owned()), domain),
        None => (None, who),
    };
    if domain.is_empty() || domain.contains(char::is_whitespace) || domain.contains('/') {
        return None;
    }
    let address = lines.next()?.to_owned();
    if address.is_empty() || address.contains(char::is_whitespace) || !lines.next()?.is_empty() {
        return None;
    }
    // Either an empty line (no statement), or the statement and then an empty line.
    let statement = match lines.next()? {
        "" => None,
        line => {
            if !lines.next()?.is_empty() {
                return None;
            }
            Some(line.to_owned())
        }
    };
    let mut field =
        |name: &str| -> Option<String> { lines.next()?.strip_prefix(name).map(str::to_owned) };
    let uri = field("URI: ")?;
    let version = field("Version: ")?;
    let chain_id = field("Chain ID: ")?;
    let nonce = field("Nonce: ")?;
    let issued_at = field("Issued At: ")?;
    let mut rest: Vec<&str> = lines.collect();
    rest.reverse();
    let mut optional = |name: &str| -> Option<String> {
        let value = rest.last()?.strip_prefix(name)?.to_owned();
        rest.pop();
        Some(value)
    };
    let expiration_time = optional("Expiration Time: ");
    let not_before = optional("Not Before: ");
    let request_id = optional("Request ID: ");
    let mut resources = Vec::new();
    if rest.last() == Some(&"Resources:") {
        rest.pop();
        while let Some(resource) = rest.last().and_then(|l| l.strip_prefix("- ")) {
            resources.push(resource.to_owned());
            rest.pop();
        }
    }
    if !rest.is_empty() || nonce.is_empty() || version != "1" {
        return None;
    }
    Some(Siwe {
        scheme,
        domain: domain.to_owned(),
        address,
        statement,
        uri,
        version,
        chain_id,
        nonce,
        issued_at,
        expiration_time,
        not_before,
        request_id,
        resources,
    })
}

/// The scheme and the authority (`host[:port]`, lower case, default port dropped) of an origin.
fn split_origin(origin: &str) -> Option<(String, String)> {
    let (scheme, rest) = origin.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?.to_ascii_lowercase();
    let scheme = scheme.to_ascii_lowercase();
    let default = match scheme.as_str() {
        "https" => ":443",
        "http" => ":80",
        _ => "",
    };
    let authority = match authority.strip_suffix(default) {
        Some(host) if !default.is_empty() => host.to_owned(),
        _ => authority,
    };
    (!authority.is_empty()).then_some((scheme, authority))
}

/// Whether the message's claimed domain (and scheme, if it names one) is the origin's.
fn domain_matches(siwe: &Siwe, origin: &str) -> bool {
    let Some((scheme, authority)) = split_origin(origin) else { return false };
    let claimed = siwe.domain.to_ascii_lowercase();
    let claimed = match claimed.strip_suffix(if scheme == "https" { ":443" } else { ":80" }) {
        Some(host) => host.to_owned(),
        None => claimed,
    };
    claimed == authority && siwe.scheme.as_ref().is_none_or(|s| s.eq_ignore_ascii_case(&scheme))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const SIGNER: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";

    fn message(domain: &str, statement: Option<&str>) -> String {
        let statement = statement.map_or_else(|| "\n".to_owned(), |s| format!("{s}\n\n"));
        format!(
            "{domain} wants you to sign in with your Ethereum account:\n{SIGNER}\n\n{statement}URI: https://{domain}/login\nVersion: 1\nChain ID: 1\nNonce: 32891756\nIssued At: 2026-10-28T12:00:00Z\nExpiration Time: 2026-10-28T13:00:00Z\nResources:\n- https://example.com/a\n- ipfs://abc"
        )
    }

    #[test]
    fn a_sign_in_message_is_parsed() {
        for statement in [Some("I accept the terms."), None] {
            let parsed = parse_siwe(&message("example.com", statement), "Ethereum").unwrap();
            assert_eq!(parsed.domain, "example.com");
            assert_eq!(parsed.address, SIGNER);
            assert_eq!(parsed.statement.as_deref(), statement);
            assert_eq!(parsed.chain_id, "1");
            assert_eq!(parsed.nonce, "32891756");
            assert_eq!(parsed.expiration_time.as_deref(), Some("2026-10-28T13:00:00Z"));
            assert_eq!(parsed.resources, ["https://example.com/a", "ipfs://abc"]);
        }
    }

    #[test]
    fn departures_from_the_layout_are_not_parsed() {
        let good = message("example.com", None);
        for broken in [
            good.replace("Version: 1", "Version: 2"),
            good.replace("Nonce: 32891756\n", ""),
            format!("{good}\nextra line"),
            good.replace("Ethereum account", "Solana account"),
            good.replace("example.com wants", "evil.com/path wants"),
        ] {
            assert_eq!(parse_siwe(&broken, "Ethereum"), None, "{broken}");
        }
    }

    #[test]
    fn the_claimed_domain_is_compared_with_the_origin() {
        let details = |domain: &str, origin: Option<&str>| {
            message_details(message(domain, None).as_bytes(), "Ethereum", SIGNER, origin)
        };
        let ok = details("example.com", Some("https://example.com"));
        assert_eq!(ok["siwe"]["domain_matches_origin"], json!(true));
        assert!(message_warnings(&ok).is_empty());
        let wrong = details("bank.example", Some("https://evil.example"));
        assert_eq!(wrong["siwe"]["domain_matches_origin"], json!(false));
        assert_eq!(wrong["siwe"]["claimed_domain"], "bank.example");
        assert!(message_warnings(&wrong).contains(&warning::SIWE_DOMAIN_MISMATCH));
        // A port, a default port, upper case, a subdomain.
        assert_eq!(
            details("localhost:3000", Some("http://localhost:3000"))["siwe"]["domain_matches_origin"],
            json!(true)
        );
        assert_eq!(
            details("example.com:443", Some("https://example.com"))["siwe"]["domain_matches_origin"],
            json!(true)
        );
        assert_eq!(
            details("EXAMPLE.com", Some("https://example.com/x"))["siwe"]["domain_matches_origin"],
            json!(true)
        );
        assert_eq!(
            details("example.com", Some("https://example.com.evil.io"))["siwe"]["domain_matches_origin"],
            json!(false)
        );
        assert_eq!(
            details("example.com", Some("https://app.example.com"))["siwe"]["domain_matches_origin"],
            json!(false)
        );
        // No origin given: nothing is claimed either way.
        assert_eq!(details("example.com", None)["siwe"]["domain_matches_origin"], Value::Null);
    }

    #[test]
    fn another_address_than_the_signer_is_flagged() {
        let other = message("example.com", None)
            .replace(SIGNER, "0x1111111111111111111111111111111111111111");
        let details = message_details(other.as_bytes(), "Ethereum", SIGNER, None);
        assert!(message_warnings(&details).contains(&warning::SIWE_ADDRESS_MISMATCH));
    }

    #[test]
    fn hidden_characters_and_a_broken_sign_in_message_are_flagged() {
        let hidden = message_details("pay \u{202E}0.1 ETH".as_bytes(), "Ethereum", SIGNER, None);
        assert_eq!(hidden["text"], Value::Null);
        assert_eq!(hidden["text_escaped"], "pay <U+202E>0.1 ETH");
        assert_eq!(hidden["hidden_characters"], 1);
        assert_eq!(
            message_warnings(&hidden),
            [warning::UNREADABLE_MESSAGE, warning::HIDDEN_CHARACTERS]
        );
        let broken = message_details(
            b"evil.example wants you to sign in with your Ethereum account:\nnot an address",
            "Ethereum",
            SIGNER,
            Some("https://evil.example"),
        );
        assert!(message_warnings(&broken).contains(&warning::SIWE_MALFORMED));
        let plain = message_details(b"hello", "Ethereum", SIGNER, None);
        assert_eq!(
            (plain["message_len"].as_u64(), plain["text_chars"].as_u64()),
            (Some(5), Some(5))
        );
        assert!(message_warnings(&plain).is_empty());
    }
}
