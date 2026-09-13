// SPDX-License-Identifier: AGPL-3.0-only
//! Reproduce the frozen evaluator's urlsplit/form-query identity without WHATWG path repair.
//! Raw paths retain case, percent spelling, dot segments and interior slashes.
//! Normalized identities are used only for evaluation, never retrieval-stage merging.

use super::{input::MAX_URL_BYTES, EvalError};

fn encode(text: &str) -> String {
    let mut output = String::new();
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                output.push(char::from(byte))
            }
            b' ' => output.push('+'),
            _ => output.push_str(&format!("%{byte:02X}")),
        }
    }
    output
}

/// Normalize a bounded URL with the frozen Python evaluator's page-identity semantics.
/// Invalid bracket/port syntax and URL strings above 8192 bytes return typed errors.
pub fn normalize(input: &str) -> Result<String, EvalError> {
    if input.len() > MAX_URL_BYTES {
        return Err(EvalError::UrlLimit);
    }
    if input.chars().any(char::is_control) {
        return Err(EvalError::InvalidUrl);
    }
    let fragmentless = input.split('#').next().ok_or(EvalError::InvalidUrl)?;
    let (base, query) = fragmentless.split_once('?').unwrap_or((fragmentless, ""));
    let mut rest = base;
    if let Some((scheme, tail)) = base.split_once(':') {
        if scheme
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
            && scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
        {
            rest = tail;
        }
    }
    let (authority, path) = if let Some(without_slashes) = rest.strip_prefix("//") {
        match without_slashes.find('/') {
            Some(i) => (&without_slashes[..i], &without_slashes[i..]),
            None => (without_slashes, ""),
        }
    } else {
        ("", rest)
    };
    let authority = authority.rsplit('@').next().ok_or(EvalError::InvalidUrl)?;
    let (host, port) = if let Some(ipv6) = authority.strip_prefix('[') {
        let (host, suffix) = ipv6.split_once(']').ok_or(EvalError::InvalidUrl)?;
        host.parse::<std::net::Ipv6Addr>()
            .map_err(|_| EvalError::InvalidUrl)?;
        let port = if suffix.is_empty() {
            ""
        } else {
            suffix.strip_prefix(':').ok_or(EvalError::InvalidUrl)?
        };
        (host, port)
    } else {
        if authority.contains(['[', ']']) || authority.matches(':').count() > 1 {
            return Err(EvalError::InvalidUrl);
        }
        authority.split_once(':').unwrap_or((authority, ""))
    };
    let port = if port.is_empty() {
        None
    } else {
        if !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err(EvalError::InvalidUrl);
        }
        Some(port.parse::<u16>().map_err(|_| EvalError::InvalidUrl)?)
    };
    let host = host.to_lowercase();
    let mut output = host.strip_prefix("www.").unwrap_or(&host).to_owned();
    if let Some(port) = port.filter(|p| ![0, 80, 443].contains(p)) {
        output.push_str(&format!(":{port}"));
    }
    let path = path.trim_end_matches('/');
    output.push_str(if path.is_empty() { "/" } else { path });
    let mut pairs: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
        .filter_map(|(key, value)| {
            let folded = key.to_lowercase();
            if folded.starts_with("utm_") || folded == "gclid" || folded == "fbclid" {
                None
            } else {
                Some((key.into_owned(), value.into_owned()))
            }
        })
        .collect();
    pairs.sort();
    if !pairs.is_empty() {
        output.push('?');
        for (i, (key, value)) in pairs.iter().enumerate() {
            if i > 0 {
                output.push('&');
            }
            output.push_str(&encode(key));
            output.push('=');
            output.push_str(&encode(value));
        }
    }
    Ok(output)
}
