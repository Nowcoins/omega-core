//! Reading fields out of a request. Messages name the field, never its value.

use serde_json::{Map, Value};

use super::SigningError;

pub(crate) type Obj = Map<String, Value>;

pub(crate) fn bad(detail: impl Into<String>) -> SigningError {
    SigningError::new("BadRequest", detail)
}

pub(crate) fn as_object<'a>(value: &'a Value, what: &str) -> Result<&'a Obj, SigningError> {
    value.as_object().ok_or_else(|| bad(format!("{what} is not an object")))
}

/// Refuses a field `allowed` does not list: our own requests carry exactly
/// their fields.
pub(crate) fn only(map: &Obj, allowed: &[&str], what: &str) -> Result<(), SigningError> {
    match map.keys().find(|key| !allowed.contains(&key.as_str())) {
        Some(_) => Err(bad(format!("{what} has a field that is not part of it"))),
        None => Ok(()),
    }
}

pub(crate) fn get<'a>(map: &'a Obj, key: &str) -> Result<&'a Value, SigningError> {
    map.get(key).ok_or_else(|| bad(format!("{key} is missing")))
}

pub(crate) fn string<'a>(map: &'a Obj, key: &str) -> Result<&'a str, SigningError> {
    get(map, key)?.as_str().ok_or_else(|| bad(format!("{key} is not a string")))
}

pub(crate) fn opt_string<'a>(map: &'a Obj, key: &str) -> Result<Option<&'a str>, SigningError> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(bad(format!("{key} is not a string"))),
    }
}

pub(crate) fn object<'a>(map: &'a Obj, key: &str) -> Result<&'a Obj, SigningError> {
    get(map, key)?.as_object().ok_or_else(|| bad(format!("{key} is not an object")))
}

pub(crate) fn opt_object<'a>(map: &'a Obj, key: &str) -> Result<Option<&'a Obj>, SigningError> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(inner)) => Ok(Some(inner)),
        Some(_) => Err(bad(format!("{key} is not an object"))),
    }
}

pub(crate) fn array<'a>(map: &'a Obj, key: &str) -> Result<&'a Vec<Value>, SigningError> {
    get(map, key)?.as_array().ok_or_else(|| bad(format!("{key} is not an array")))
}

pub(crate) fn flag(map: &Obj, key: &str) -> Result<bool, SigningError> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(flag)) => Ok(*flag),
        Some(_) => Err(bad(format!("{key} is not true or false"))),
    }
}

/// A decimal number written as text: digits only.
fn decimal(text: &str, key: &str) -> Result<u128, SigningError> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad(format!("{key} is not a decimal number")));
    }
    text.parse::<u128>().map_err(|_| bad(format!("{key} is too large")))
}

/// Our own numbers: decimal strings, never JSON numbers.
pub(crate) fn decimal_u128(map: &Obj, key: &str) -> Result<u128, SigningError> {
    decimal(string(map, key)?, key)
}

pub(crate) fn decimal_u64(map: &Obj, key: &str) -> Result<u64, SigningError> {
    u64::try_from(decimal_u128(map, key)?).map_err(|_| bad(format!("{key} is too large")))
}

/// A number from the wallet API's bodies: a JSON integer or a decimal string.
pub(crate) fn api_u128(map: &Obj, key: &str) -> Result<u128, SigningError> {
    match get(map, key)? {
        Value::String(text) => decimal(text, key),
        Value::Number(number) => number
            .as_u64()
            .map(u128::from)
            .ok_or_else(|| bad(format!("{key} is not a whole number"))),
        _ => Err(bad(format!("{key} is not a number"))),
    }
}

pub(crate) fn api_u64(map: &Obj, key: &str) -> Result<u64, SigningError> {
    u64::try_from(api_u128(map, key)?).map_err(|_| bad(format!("{key} is too large")))
}

pub(crate) fn api_u32(map: &Obj, key: &str) -> Result<u32, SigningError> {
    u32::try_from(api_u128(map, key)?).map_err(|_| bad(format!("{key} is too large")))
}

/// Like [`api_u128`] for a field that may be absent or null.
pub(crate) fn opt_api_u128(map: &Obj, key: &str) -> Result<Option<u128>, SigningError> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => api_u128(map, key).map(Some),
    }
}
