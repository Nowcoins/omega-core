//! EIP-712 typed structured data: the hash a wallet signs, from the JSON a
//! dApp sends (`eth_signTypedData_v4`: `types`, `primaryType`, `domain`,
//! `message`).
//!
//! Written from the specification and checked against its worked example, the
//! test suites of MetaMask's `eth-sig-util` and Trust Wallet Core
//! (`tests/evm_messages.rs`). It is deliberately stricter than those
//! libraries about what it accepts:
//!
//! * every member of a struct must be present in the message, and none may be
//!   `null` (a missing value is never read as zero);
//! * an integer is a JSON integer, a decimal string or a `0x` hex string, and
//!   must fit its declared width; a boolean is a JSON boolean; an address is
//!   `0x` and 40 hex digits; `bytesN` is `0x` and hex digits for at most `N`
//!   bytes, and `bytes` is `0x` and hex digits (a shorter `bytesN` is
//!   zero-padded at the end, and a hex string of odd length is read with a
//!   zero in front, as MetaMask and Trust Wallet read them);
//! * `uint` and `int` without a width are refused, as are type and member
//!   names that are not identifiers;
//! * a fixed-size array must hold exactly its length.
//!
//! Members of the message that the type does not declare are ignored, as the
//! specification's `encodeData` does; the summary for an approval screen
//! ([`TypedData::summary`]) reports what is signed, so a wallet that shows
//! the summary shows what the signature covers.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde_json::Value;

use super::tx::keccak;
use super::u256::U256;
use crate::ecdsa::{RecoverableSignature, sign_digest};
use crate::hexutil;
use crate::key::SigningKey;
use crate::tx_error::TxError;

/// How deep a struct may nest in the data, a guard on recursion.
const MAX_DEPTH: usize = 32;

fn err(path: &str, reason: &str) -> TxError {
    if path.is_empty() {
        TxError::TypedData(reason.to_owned())
    } else {
        TxError::TypedData(format!("{path}: {reason}"))
    }
}

/// One member of a struct type.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Member {
    name: String,
    ty: String,
}

/// A parsed type: what it is made of, and its array dimensions from the
/// inside out (`uint8[2][]` is `Uint(8)` with dimensions `[Some(2), None]`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct TypeRef {
    base: Base,
    dims: Vec<Option<usize>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Base {
    Bool,
    Address,
    Uint(u32),
    Int(u32),
    FixedBytes(usize),
    Bytes,
    String,
    Struct(String),
}

fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Splits `uint8[2][]` into its base `uint8` and dimensions.
fn parse_type(text: &str) -> Result<TypeRef, TxError> {
    let mut rest = text;
    let mut dims = Vec::new();
    while let Some(open) = rest.strip_suffix(']') {
        let start =
            open.rfind('[').ok_or_else(|| err("", &format!("the type {text} is malformed")))?;
        let inside = &open[start + 1..];
        dims.push(if inside.is_empty() {
            None
        } else if inside.bytes().all(|b| b.is_ascii_digit()) && !inside.starts_with('0') {
            Some(
                inside
                    .parse::<usize>()
                    .map_err(|_| err("", &format!("the array length in {text} is too large")))?,
            )
        } else {
            return Err(err("", &format!("the array length in {text} is not a number")));
        });
        rest = &open[..start];
    }
    dims.reverse();
    let base = match rest {
        "bool" => Base::Bool,
        "address" => Base::Address,
        "bytes" => Base::Bytes,
        "string" => Base::String,
        _ => {
            if let Some(width) = rest.strip_prefix("uint") {
                Base::Uint(int_width(width, text)?)
            } else if let Some(width) = rest.strip_prefix("int") {
                Base::Int(int_width(width, text)?)
            } else if let Some(width) = rest.strip_prefix("bytes") {
                let n: usize = width
                    .parse()
                    .ok()
                    .filter(|n| (1..=32).contains(n) && width.bytes().all(|b| b.is_ascii_digit()))
                    .ok_or_else(|| err("", &format!("{text} is not a type")))?;
                Base::FixedBytes(n)
            } else if is_identifier(rest) {
                Base::Struct(rest.to_owned())
            } else {
                return Err(err("", &format!("{text} is not a type")));
            }
        }
    };
    Ok(TypeRef { base, dims })
}

fn int_width(width: &str, whole: &str) -> Result<u32, TxError> {
    width
        .parse::<u32>()
        .ok()
        .filter(|w| {
            w % 8 == 0 && (8..=256).contains(w) && width.bytes().all(|b| b.is_ascii_digit())
        })
        .ok_or_else(|| err("", &format!("{whole} needs a width: 8 to 256 in steps of 8")))
}

/// Uniswap's Permit2 contract, deployed at this address on every EVM chain this
/// wallet serves.
pub const PERMIT2: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0xD4, 0x73, 0x03, 0x0F, 0x11, 0x6d, 0xDE, 0xE9, 0xF6, 0xB4,
    0x3a, 0xC7, 0x8B, 0xA3,
];

/// What the wallet itself knows a contract to be, as against what a signed
/// message says about itself.
#[must_use]
pub fn known_contract_name(address: &[u8; 20]) -> Option<&'static str> {
    (*address == PERMIT2).then_some("Permit2")
}

/// The domain fields of a typed-data request that a wallet shows.
///
/// `name` and `version` are **claimed by the site**: any contract and any site
/// can write any name. Only `verifying_contract` can be compared with an address
/// the wallet knows ([`known_contract_name`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DomainInfo {
    /// `domain.name`.
    pub name: Option<String>,
    /// `domain.version`.
    pub version: Option<String>,
    /// `domain.chainId`. A wallet must check it against the chain it is on.
    pub chain_id: Option<U256>,
    /// `domain.verifyingContract`.
    pub verifying_contract: Option<[u8; 20]>,
    /// `domain.salt`.
    pub salt: Option<[u8; 32]>,
}

/// What a typed-data request asks the user to sign, for an approval screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedDataSummary {
    /// The `primaryType` of the message.
    pub primary_type: String,
    /// The signing domain.
    pub domain: DomainInfo,
    /// What the message is, when it is one the wallet recognises.
    pub kind: TypedDataKind,
}

/// Messages a wallet recognises and can describe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypedDataKind {
    /// An EIP-2612 `permit`: a signature that lets `spender` take `value` of
    /// the owner's token (the `verifyingContract` of the domain) with no
    /// transaction from the owner. As dangerous as an `approve`.
    Permit {
        /// Whose tokens.
        owner: [u8; 20],
        /// Who may spend them.
        spender: [u8; 20],
        /// How much, in the token's base units.
        value: U256,
        /// True when `value` is a maximum no one means as an amount
        /// ([`U256::is_unlimited`]).
        unlimited: bool,
        /// The owner's permit nonce.
        nonce: U256,
        /// Until when (a Unix time, seconds).
        deadline: U256,
    },
    /// The permit of DAI and its kin (`holder`, `spender`, `nonce`, `expiry`,
    /// `allowed`): all of the holder's tokens, until revoked.
    DaiPermit {
        /// Whose tokens.
        holder: [u8; 20],
        /// Who may spend them.
        spender: [u8; 20],
        /// The holder's permit nonce.
        nonce: U256,
        /// Until when (a Unix time, seconds; 0 for no expiry).
        expiry: U256,
        /// Whether the permission is granted or taken away.
        allowed: bool,
    },
    /// Permit2's `PermitSingle` or `PermitBatch`: `spender` may take the listed
    /// tokens from the signer, up to each amount, until each one's expiry, with no
    /// transaction from the signer. As dangerous as an `approve` for each.
    Permit2Allowance {
        /// One entry for `PermitSingle`, one or more for `PermitBatch`.
        details: Vec<Permit2Allowance>,
        /// Who may spend.
        spender: [u8; 20],
        /// Until when the signature may be used (Unix seconds).
        sig_deadline: U256,
        /// Whether this is a `PermitBatch`.
        batch: bool,
    },
    /// Permit2's `PermitTransferFrom`, `PermitBatchTransferFrom` and their
    /// witness variants: a signature with which `spender` can move **up to** each
    /// listed amount out of the signer's account, once (the nonce is used up), to
    /// any address the spender names when it calls Permit2. With a witness, the
    /// spender's call must also match the witness data, which is shown only as a
    /// type name here (read the data).
    Permit2Transfer {
        /// The tokens and the most of each that may move.
        permitted: Vec<Permit2Token>,
        /// Who may move them.
        spender: [u8; 20],
        /// The signature's one-time number.
        nonce: U256,
        /// Until when the signature may be used (Unix seconds).
        deadline: U256,
        /// The witness struct's type name, for the witness variants.
        witness_type: Option<String>,
        /// Whether this is a batch variant.
        batch: bool,
    },
    /// Any other message: the wallet can show the primary type and the
    /// domain, and the data itself.
    Other,
}

/// One token of a Permit2 `PermitDetails`: an allowance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permit2Allowance {
    /// The token contract.
    pub token: [u8; 20],
    /// How much, in base units (a `uint160`).
    pub amount: U256,
    /// A maximum no one means as an amount, the `uint160` maximum included.
    pub unlimited: bool,
    /// When the allowance ends (Unix seconds, a `uint48`).
    pub expiration: U256,
    /// Whether that is so far off (past the year 2106) that it never ends in
    /// practice.
    pub never_expires: bool,
    /// The allowance's nonce.
    pub nonce: U256,
}

/// One token of a Permit2 `TokenPermissions`: the most that may move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permit2Token {
    /// The token contract.
    pub token: [u8; 20],
    /// The most, in base units.
    pub amount: U256,
    /// A maximum no one means as an amount.
    pub unlimited: bool,
}

/// EIP-712 typed data, parsed and checked.
#[derive(Debug, Clone)]
pub struct TypedData {
    types: BTreeMap<String, Vec<Member>>,
    primary_type: String,
    domain: Value,
    message: Value,
}

impl TypedData {
    /// Parses the JSON of an `eth_signTypedData_v4` request's data: an object
    /// with `types`, `primaryType`, `domain` and `message`.
    pub fn parse(json: &str) -> Result<Self, TxError> {
        let root: Value = serde_json::from_str(json).map_err(|_| err("", "not valid JSON"))?;
        Self::from_value(&root)
    }

    /// [`Self::parse`] from JSON already read.
    pub fn from_value(root: &Value) -> Result<Self, TxError> {
        let object = root.as_object().ok_or_else(|| err("", "not a JSON object"))?;
        let primary_type = object
            .get("primaryType")
            .and_then(Value::as_str)
            .ok_or_else(|| err("primaryType", "missing or not a string"))?
            .to_owned();
        let raw_types = object
            .get("types")
            .and_then(Value::as_object)
            .ok_or_else(|| err("types", "missing or not an object"))?;
        let mut types = BTreeMap::new();
        for (name, members) in raw_types {
            if !is_identifier(name) {
                return Err(err("types", &format!("{name} is not a name")));
            }
            if !matches!(parse_type(name)?.base, Base::Struct(_)) {
                return Err(err("types", &format!("{name} is the name of a built-in type")));
            }
            let list =
                members.as_array().ok_or_else(|| err(&format!("types.{name}"), "not an array"))?;
            let mut parsed = Vec::with_capacity(list.len());
            let mut seen = BTreeSet::new();
            for member in list {
                let field = member
                    .as_object()
                    .ok_or_else(|| err(&format!("types.{name}"), "a member is not an object"))?;
                let member_name = field
                    .get("name")
                    .and_then(Value::as_str)
                    .filter(|n| is_identifier(n))
                    .ok_or_else(|| err(&format!("types.{name}"), "a member has no valid name"))?;
                let member_type = field
                    .get("type")
                    .and_then(Value::as_str)
                    .ok_or_else(|| err(&format!("types.{name}.{member_name}"), "has no type"))?;
                if !seen.insert(member_name.to_owned()) {
                    return Err(err(&format!("types.{name}"), "a member is listed twice"));
                }
                parsed.push(Member { name: member_name.to_owned(), ty: member_type.to_owned() });
            }
            types.insert(name.clone(), parsed);
        }
        let data = Self {
            types,
            primary_type,
            domain: object.get("domain").cloned().ok_or_else(|| err("domain", "missing"))?,
            message: object.get("message").cloned().unwrap_or(Value::Null),
        };
        // Every type used must be defined, and every type name must parse:
        // checked now, so nothing later meets a surprise.
        for (name, members) in &data.types {
            for member in members {
                let parsed = parse_type(&member.ty)?;
                if let Base::Struct(target) = parsed.base
                    && !data.types.contains_key(&target)
                {
                    return Err(err(
                        &format!("types.{name}.{}", member.name),
                        &format!("the type {target} is not defined"),
                    ));
                }
            }
        }
        if !data.types.contains_key("EIP712Domain") {
            return Err(err("types", "EIP712Domain is not defined"));
        }
        if !data.types.contains_key(&data.primary_type) {
            return Err(err("primaryType", "is not one of the types"));
        }
        Ok(data)
    }

    /// The `primaryType`.
    #[must_use]
    pub fn primary_type(&self) -> &str {
        &self.primary_type
    }

    /// `encodeType` of a struct: its definition, then its dependencies in
    /// alphabetical order, e.g. `Mail(Person from,Person to,string
    /// contents)Person(string name,address wallet)`.
    pub fn encode_type(&self, name: &str) -> Result<String, TxError> {
        if !self.types.contains_key(name) {
            return Err(err("", &format!("the type {name} is not defined")));
        }
        let mut dependencies = BTreeSet::new();
        self.collect_dependencies(name, &mut dependencies)?;
        dependencies.remove(name);
        let mut out = String::new();
        for ty in std::iter::once(name).chain(dependencies.iter().map(String::as_str)) {
            out.push_str(ty);
            out.push('(');
            let members = &self.types[ty];
            for (i, member) in members.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&member.ty);
                out.push(' ');
                out.push_str(&member.name);
            }
            out.push(')');
        }
        Ok(out)
    }

    fn collect_dependencies(
        &self,
        name: &str,
        found: &mut BTreeSet<String>,
    ) -> Result<(), TxError> {
        if !found.insert(name.to_owned()) {
            return Ok(());
        }
        for member in self.types.get(name).map_or(&[][..], Vec::as_slice) {
            if let Base::Struct(target) = parse_type(&member.ty)?.base {
                self.collect_dependencies(&target, found)?;
            }
        }
        Ok(())
    }

    /// `hashStruct(domain)`: the domain separator.
    pub fn domain_separator(&self) -> Result<[u8; 32], TxError> {
        Hasher::new(self).hash_struct("EIP712Domain", &self.domain, "domain", 0)
    }

    /// `hashStruct(message)`.
    pub fn message_hash(&self) -> Result<[u8; 32], TxError> {
        Hasher::new(self).hash_struct(&self.primary_type, &self.message, "message", 0)
    }

    /// The digest that is signed: `keccak256(0x19 0x01 ‖ domainSeparator ‖
    /// hashStruct(message))`. If the primary type is `EIP712Domain` itself,
    /// the message is not part of it, as in MetaMask.
    pub fn signing_hash(&self) -> Result<[u8; 32], TxError> {
        let mut hasher = Hasher::new(self);
        let domain = hasher.hash_struct("EIP712Domain", &self.domain, "domain", 0)?;
        let mut preimage = Vec::with_capacity(66);
        preimage.extend_from_slice(&[0x19, 0x01]);
        preimage.extend_from_slice(&domain);
        if self.primary_type != "EIP712Domain" {
            let message = hasher.hash_struct(&self.primary_type, &self.message, "message", 0)?;
            preimage.extend_from_slice(&message);
        }
        Ok(keccak(&preimage))
    }

    /// Signs the typed data with `key`: the signature `eth_signTypedData_v4`
    /// returns (as `r ‖ s ‖ v` with `v` 27 or 28, see
    /// [`RecoverableSignature::to_rsv`]).
    pub fn sign(&self, key: &SigningKey) -> Result<RecoverableSignature, TxError> {
        sign_digest(key, &self.signing_hash()?)
    }

    /// The domain, as far as it names the usual fields.
    pub fn domain_info(&self) -> Result<DomainInfo, TxError> {
        let object = self.domain.as_object().ok_or_else(|| err("domain", "not an object"))?;
        let mut info = DomainInfo::default();
        for member in &self.types["EIP712Domain"] {
            let value = object.get(&member.name);
            let path = format!("domain.{}", member.name);
            match (member.name.as_str(), value) {
                ("name", Some(Value::String(s))) => info.name = Some(s.clone()),
                ("version", Some(Value::String(s))) => info.version = Some(s.clone()),
                ("chainId", Some(v)) => info.chain_id = Some(Hasher::uint256(v, &path)?),
                ("verifyingContract", Some(v)) => {
                    info.verifying_contract = Some(Hasher::address(v, &path)?);
                }
                ("salt", Some(v)) => info.salt = Some(Hasher::fixed_bytes::<32>(v, &path)?),
                _ => {}
            }
        }
        Ok(info)
    }

    /// What the message asks the user to sign, for an approval screen. Runs
    /// the full hash first, so a malformed request is an error here and not
    /// something half described.
    pub fn summary(&self) -> Result<TypedDataSummary, TxError> {
        self.signing_hash()?;
        let domain = self.domain_info()?;
        let kind = self.kind()?;
        Ok(TypedDataSummary { primary_type: self.primary_type.clone(), domain, kind })
    }

    fn kind(&self) -> Result<TypedDataKind, TxError> {
        let shape = |wanted: &[(&str, &str)]| {
            let members = &self.types[&self.primary_type];
            members.len() == wanted.len()
                && members.iter().zip(wanted).all(|(m, (n, t))| m.name == *n && m.ty == *t)
        };
        let message = self.message.as_object();
        let field = |name: &str| -> Result<&Value, TxError> {
            message
                .and_then(|m| m.get(name))
                .ok_or_else(|| err(&format!("message.{name}"), "missing"))
        };
        if self.primary_type == "Permit"
            && shape(&[
                ("owner", "address"),
                ("spender", "address"),
                ("value", "uint256"),
                ("nonce", "uint256"),
                ("deadline", "uint256"),
            ])
        {
            let value = Hasher::uint256(field("value")?, "message.value")?;
            return Ok(TypedDataKind::Permit {
                owner: Hasher::address(field("owner")?, "message.owner")?,
                spender: Hasher::address(field("spender")?, "message.spender")?,
                unlimited: value.is_unlimited(),
                value,
                nonce: Hasher::uint256(field("nonce")?, "message.nonce")?,
                deadline: Hasher::uint256(field("deadline")?, "message.deadline")?,
            });
        }
        if self.primary_type == "Permit"
            && shape(&[
                ("holder", "address"),
                ("spender", "address"),
                ("nonce", "uint256"),
                ("expiry", "uint256"),
                ("allowed", "bool"),
            ])
        {
            return Ok(TypedDataKind::DaiPermit {
                holder: Hasher::address(field("holder")?, "message.holder")?,
                spender: Hasher::address(field("spender")?, "message.spender")?,
                nonce: Hasher::uint256(field("nonce")?, "message.nonce")?,
                expiry: Hasher::uint256(field("expiry")?, "message.expiry")?,
                allowed: field("allowed")?
                    .as_bool()
                    .ok_or_else(|| err("message.allowed", "not a boolean"))?,
            });
        }
        if let Some(kind) = self.permit2()? {
            return Ok(kind);
        }
        Ok(TypedDataKind::Other)
    }

    /// Whether the struct type `name` has exactly these members, in this order.
    fn has_shape(&self, name: &str, wanted: &[(&str, &str)]) -> bool {
        self.types.get(name).is_some_and(|members| {
            members.len() == wanted.len()
                && members.iter().zip(wanted).all(|(m, (n, t))| m.name == *n && m.ty == *t)
        })
    }

    /// Permit2's four signed structs, and the two witness variants, by shape.
    fn permit2(&self) -> Result<Option<TypedDataKind>, TxError> {
        let primary = self.primary_type.as_str();
        let members = &self.types[primary];
        let word = |field: &str| -> Result<&Value, TxError> {
            self.message.get(field).ok_or_else(|| err(&format!("message.{field}"), "missing"))
        };
        let details_ok = self.has_shape(
            "PermitDetails",
            &[
                ("token", "address"),
                ("amount", "uint160"),
                ("expiration", "uint48"),
                ("nonce", "uint48"),
            ],
        );
        let batch_single = |batch: bool| -> [(&str, String); 3] {
            [
                ("details", if batch { "PermitDetails[]" } else { "PermitDetails" }.to_owned()),
                ("spender", "address".to_owned()),
                ("sigDeadline", "uint256".to_owned()),
            ]
        };
        for batch in [false, true] {
            let wanted = batch_single(batch);
            let wanted: Vec<(&str, &str)> = wanted.iter().map(|(n, t)| (*n, t.as_str())).collect();
            if details_ok
                && primary == if batch { "PermitBatch" } else { "PermitSingle" }
                && self.has_shape(primary, &wanted)
            {
                let one = |value: &Value, path: &str| -> Result<Permit2Allowance, TxError> {
                    let field = |n: &str| {
                        value.get(n).ok_or_else(|| err(&format!("{path}.{n}"), "missing"))
                    };
                    let amount = Hasher::uint256(field("amount")?, path)?;
                    let expiration = Hasher::uint256(field("expiration")?, path)?;
                    Ok(Permit2Allowance {
                        token: Hasher::address(field("token")?, path)?,
                        unlimited: amount.is_unlimited(),
                        amount,
                        never_expires: expiration >= U256::from_u128(u128::from(u32::MAX)),
                        expiration,
                        nonce: Hasher::uint256(field("nonce")?, path)?,
                    })
                };
                let details = if batch {
                    word("details")?
                        .as_array()
                        .ok_or_else(|| err("message.details", "not an array"))?
                        .iter()
                        .enumerate()
                        .map(|(i, d)| one(d, &format!("message.details[{i}]")))
                        .collect::<Result<Vec<_>, _>>()?
                } else {
                    vec![one(word("details")?, "message.details")?]
                };
                return Ok(Some(TypedDataKind::Permit2Allowance {
                    details,
                    spender: Hasher::address(word("spender")?, "message.spender")?,
                    sig_deadline: Hasher::uint256(word("sigDeadline")?, "message.sigDeadline")?,
                    batch,
                }));
            }
        }
        // The transfer variants: four members, and for a witness variant a fifth,
        // `witness`, of a struct type.
        let permissions_ok =
            self.has_shape("TokenPermissions", &[("token", "address"), ("amount", "uint256")]);
        for batch in [false, true] {
            let permitted_type = if batch { "TokenPermissions[]" } else { "TokenPermissions" };
            let base = [
                ("permitted", permitted_type),
                ("spender", "address"),
                ("nonce", "uint256"),
                ("deadline", "uint256"),
            ];
            let plain = if batch { "PermitBatchTransferFrom" } else { "PermitTransferFrom" };
            let witnessed =
                if batch { "PermitBatchWitnessTransferFrom" } else { "PermitWitnessTransferFrom" };
            let witness_type = if primary == witnessed && members.len() == 5 {
                let last = &members[4];
                (last.name == "witness"
                    && matches!(parse_type(&last.ty)?, TypeRef { base: Base::Struct(_), ref dims } if dims.is_empty())
                    && members[..4].iter().zip(base).all(|(m, (n, t))| m.name == n && m.ty == t))
                .then(|| last.ty.clone())
            } else {
                None
            };
            if !permissions_ok
                || !(self.has_shape(primary, &base) && primary == plain || witness_type.is_some())
            {
                continue;
            }
            let token = |value: &Value, path: &str| -> Result<Permit2Token, TxError> {
                let field =
                    |n: &str| value.get(n).ok_or_else(|| err(&format!("{path}.{n}"), "missing"));
                let amount = Hasher::uint256(field("amount")?, path)?;
                Ok(Permit2Token {
                    token: Hasher::address(field("token")?, path)?,
                    unlimited: amount.is_unlimited(),
                    amount,
                })
            };
            let permitted = if batch {
                word("permitted")?
                    .as_array()
                    .ok_or_else(|| err("message.permitted", "not an array"))?
                    .iter()
                    .enumerate()
                    .map(|(i, d)| token(d, &format!("message.permitted[{i}]")))
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                vec![token(word("permitted")?, "message.permitted")?]
            };
            return Ok(Some(TypedDataKind::Permit2Transfer {
                permitted,
                spender: Hasher::address(word("spender")?, "message.spender")?,
                nonce: Hasher::uint256(word("nonce")?, "message.nonce")?,
                deadline: Hasher::uint256(word("deadline")?, "message.deadline")?,
                witness_type,
                batch,
            }));
        }
        Ok(None)
    }
}

/// Hashes structs of one [`TypedData`], remembering each type's hash.
struct Hasher<'a> {
    data: &'a TypedData,
    type_hashes: HashMap<String, [u8; 32]>,
}

impl<'a> Hasher<'a> {
    fn new(data: &'a TypedData) -> Self {
        Self { data, type_hashes: HashMap::new() }
    }

    fn type_hash(&mut self, name: &str) -> Result<[u8; 32], TxError> {
        if let Some(hash) = self.type_hashes.get(name) {
            return Ok(*hash);
        }
        let hash = keccak(self.data.encode_type(name)?.as_bytes());
        self.type_hashes.insert(name.to_owned(), hash);
        Ok(hash)
    }

    /// `hashStruct(name, value)`: the type hash, then each member's 32-byte
    /// encoding in the order the type declares them.
    fn hash_struct(
        &mut self,
        name: &str,
        value: &Value,
        path: &str,
        depth: usize,
    ) -> Result<[u8; 32], TxError> {
        if depth > MAX_DEPTH {
            return Err(err(path, "nests too deeply"));
        }
        let object = value.as_object().ok_or_else(|| err(path, "not an object"))?;
        let members = self
            .data
            .types
            .get(name)
            .ok_or_else(|| err(path, &format!("the type {name} is not defined")))?;
        let mut encoded = Vec::with_capacity(32 * (members.len() + 1));
        encoded.extend_from_slice(&self.type_hash(name)?);
        for member in members {
            let member_path = format!("{path}.{}", member.name);
            let member_value = object
                .get(&member.name)
                .filter(|v| !v.is_null())
                .ok_or_else(|| err(&member_path, "missing"))?;
            let ty = parse_type(&member.ty)?;
            encoded.extend_from_slice(&self.encode_value(
                &ty,
                member_value,
                &member_path,
                depth,
            )?);
        }
        Ok(keccak(&encoded))
    }

    /// One value's 32-byte encoding: atomic values as words, strings, bytes
    /// and arrays by the hash of their content, structs by `hashStruct`.
    fn encode_value(
        &mut self,
        ty: &TypeRef,
        value: &Value,
        path: &str,
        depth: usize,
    ) -> Result<[u8; 32], TxError> {
        if let Some((last, inner)) = ty.dims.split_last() {
            let items = value.as_array().ok_or_else(|| err(path, "not an array"))?;
            if let Some(length) = last
                && items.len() != *length
            {
                return Err(err(path, &format!("an array of {length} was expected")));
            }
            let element = TypeRef { base: ty.base.clone(), dims: inner.to_vec() };
            let mut joined = Vec::with_capacity(items.len() * 32);
            for (i, item) in items.iter().enumerate() {
                if item.is_null() {
                    return Err(err(&format!("{path}[{i}]"), "is null"));
                }
                joined.extend_from_slice(&self.encode_value(
                    &element,
                    item,
                    &format!("{path}[{i}]"),
                    depth,
                )?);
            }
            return Ok(keccak(&joined));
        }
        match &ty.base {
            Base::Struct(name) => self.hash_struct(name, value, path, depth + 1),
            Base::String => {
                let text = value.as_str().ok_or_else(|| err(path, "not a string"))?;
                Ok(keccak(text.as_bytes()))
            }
            Base::Bytes => {
                let text = value.as_str().ok_or_else(|| err(path, "not a hex string"))?;
                let bytes = hexutil::decode_prefixed_lenient(text)
                    .ok_or_else(|| err(path, "not 0x and hex digits"))?;
                Ok(keccak(&bytes))
            }
            Base::Bool => {
                let flag = value.as_bool().ok_or_else(|| err(path, "not a boolean"))?;
                let mut word = [0u8; 32];
                word[31] = u8::from(flag);
                Ok(word)
            }
            Base::Address => {
                let address = Self::address(value, path)?;
                let mut word = [0u8; 32];
                word[12..].copy_from_slice(&address);
                Ok(word)
            }
            Base::Uint(bits) => {
                let (negative, magnitude) = Self::integer(value, path)?;
                if negative && !magnitude.is_zero() {
                    return Err(err(path, "is negative, for an unsigned type"));
                }
                if magnitude.bit_len() > *bits {
                    return Err(err(path, &format!("does not fit {bits} bits")));
                }
                Ok(magnitude.to_be_bytes())
            }
            Base::Int(bits) => {
                let (negative, magnitude) = Self::integer(value, path)?;
                // The range is -2^(bits-1) ..= 2^(bits-1) - 1.
                let limit = U256::pow2(bits - 1).ok_or_else(|| err(path, "bad width"))?;
                if negative {
                    if magnitude > limit {
                        return Err(err(path, &format!("does not fit {bits} bits")));
                    }
                    Ok(magnitude.wrapping_neg().to_be_bytes())
                } else {
                    if magnitude >= limit {
                        return Err(err(path, &format!("does not fit {bits} bits")));
                    }
                    Ok(magnitude.to_be_bytes())
                }
            }
            Base::FixedBytes(n) => {
                let bytes = Self::fixed_bytes_value(value, *n, path)?;
                let mut word = [0u8; 32];
                word[..bytes.len()].copy_from_slice(&bytes);
                // Zero-padded at the end, as the specification has `bytesN`.
                Ok(word)
            }
        }
    }

    /// An integer: a JSON integer, a decimal string (with a minus sign for a
    /// negative number) or `0x` hex. Returns the sign and the magnitude.
    fn integer(value: &Value, path: &str) -> Result<(bool, U256), TxError> {
        match value {
            Value::Number(n) => {
                if let Some(u) = n.as_u64() {
                    Ok((false, U256::from(u)))
                } else if let Some(i) = n.as_i64() {
                    Ok((true, U256::from(i.unsigned_abs())))
                } else {
                    Err(err(path, "is not an integer (send large numbers as strings)"))
                }
            }
            Value::String(text) => {
                let (negative, digits) = match text.strip_prefix('-') {
                    Some(rest) => (true, rest),
                    None => (false, text.as_str()),
                };
                let magnitude = if digits.starts_with("0x") || digits.starts_with("0X") {
                    U256::from_hex_str(digits)
                } else {
                    U256::from_decimal_str(digits)
                };
                magnitude.map(|m| (negative, m)).ok_or_else(|| err(path, "is not a whole number"))
            }
            _ => Err(err(path, "is not a number")),
        }
    }

    fn uint256(value: &Value, path: &str) -> Result<U256, TxError> {
        match Self::integer(value, path)? {
            (false, magnitude) => Ok(magnitude),
            (true, magnitude) if magnitude.is_zero() => Ok(magnitude),
            (true, _) => Err(err(path, "is negative, for an unsigned type")),
        }
    }

    fn address(value: &Value, path: &str) -> Result<[u8; 20], TxError> {
        value
            .as_str()
            .and_then(hexutil::decode_prefixed_array::<20>)
            .ok_or_else(|| err(path, "not 0x and 40 hex digits"))
    }

    /// The bytes of a `bytesN` value: `0x` and hex digits, at least one byte
    /// and at most `n`. A value shorter than `n` is the value zero-padded at
    /// the end, which is what the contract reads (and what MetaMask and Trust
    /// Wallet sign); a longer one is refused.
    fn fixed_bytes_value(value: &Value, n: usize, path: &str) -> Result<Vec<u8>, TxError> {
        value
            .as_str()
            .and_then(hexutil::decode_prefixed_lenient)
            .filter(|b| !b.is_empty() && b.len() <= n)
            .ok_or_else(|| err(path, &format!("not 0x and from 1 to {n} bytes")))
    }

    fn fixed_bytes<const N: usize>(value: &Value, path: &str) -> Result<[u8; N], TxError> {
        let bytes = Self::fixed_bytes_value(value, N, path)?;
        let mut out = [0u8; N];
        out[..bytes.len()].copy_from_slice(&bytes);
        Ok(out)
    }
}
