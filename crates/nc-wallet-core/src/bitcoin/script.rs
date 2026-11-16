//! Output scripts: the five address forms a payment can go to, the dust limit
//! of each, and the hashes that tie a key to an address.

use ripemd::Ripemd160;
use sha2::{Digest as _, Sha256};

use super::tx::compact_size_len;
use crate::tx_error::TxError;

/// The dust relay fee nodes apply by default, in satoshis per 1,000 bytes: an
/// output worth less than it would cost to spend at this rate is dust, and a
/// transaction creating one is not relayed.
const DUST_RELAY_FEE: u64 = 3_000;

/// A script longer than this can never be spent.
const MAX_SCRIPT_SIZE: usize = 10_000;

/// The version byte of a mainnet P2PKH address.
const P2PKH_VERSION: u8 = 0x00;
/// The version byte of a mainnet P2SH address.
const P2SH_VERSION: u8 = 0x05;

/// RIPEMD-160 of SHA-256: how a public key becomes the hash an address pays.
#[must_use]
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(&Ripemd160::digest(Sha256::digest(data)));
    out
}

/// The P2WPKH script paying a key hash: `OP_0 <20 bytes>`.
#[must_use]
pub fn p2wpkh_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(22);
    script.extend_from_slice(&[0x00, 0x14]);
    script.extend_from_slice(pubkey_hash);
    script
}

/// The P2PKH script paying a key hash: `OP_DUP OP_HASH160 <hash>
/// OP_EQUALVERIFY OP_CHECKSIG`. BIP-143 signs a P2WPKH input over this, as its
/// script code.
#[must_use]
pub fn p2pkh_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.extend_from_slice(&[0x76, 0xa9, 0x14]);
    script.extend_from_slice(pubkey_hash);
    script.extend_from_slice(&[0x88, 0xac]);
    script
}

/// The key hash a P2WPKH output script pays, if that is what it is.
#[must_use]
pub fn p2wpkh_program(script: &[u8]) -> Option<[u8; 20]> {
    match script {
        [0x00, 0x14, program @ ..] => program.try_into().ok(),
        _ => None,
    }
}

/// Whether nothing can ever spend an output with this script.
#[must_use]
pub fn is_unspendable(script: &[u8]) -> bool {
    script.first() == Some(&0x6a) || script.len() > MAX_SCRIPT_SIZE
}

/// Whether this script is a segwit program: a version opcode, then one push
/// of 2 to 40 bytes and nothing else.
#[must_use]
pub fn is_witness_program(script: &[u8]) -> bool {
    match script {
        [version, length, program @ ..] => {
            (*version == 0x00 || (0x51..=0x60).contains(version))
                && (2..=40).contains(&program.len())
                && usize::from(*length) == program.len()
        }
        _ => false,
    }
}

/// The smallest amount an output with this script can hold and still be
/// relayed, in satoshis: 546 for P2PKH, 540 for P2SH, 294 for P2WPKH, 330
/// for P2WSH and P2TR.
///
/// Bitcoin Core's own rule: what the output and a typical input spending it
/// would cost at the dust relay fee, counting a witness input's signature at a
/// quarter of its size.
#[must_use]
pub fn dust_limit(script: &[u8]) -> u64 {
    if is_unspendable(script) {
        return 0;
    }
    let output = 8 + compact_size_len(script.len() as u64) + script.len() as u64;
    // An outpoint (36), a script length (1), a sequence (4), and a 107-byte
    // signature and key: in the script, or in the witness at a quarter.
    let spend =
        if is_witness_program(script) { 32 + 4 + 1 + 107 / 4 + 4 } else { 32 + 4 + 1 + 107 + 4 };
    ((output + spend) * DUST_RELAY_FEE).div_ceil(1_000)
}

/// The output script that pays a mainnet address: P2PKH (`1…`), P2SH (`3…`),
/// P2WPKH and P2WSH (`bc1q…`) or P2TR (`bc1p…`). Anything else is refused: a
/// testnet address, a witness version with no rules yet (coins sent to one
/// could be taken by anyone), a checksum that does not match, or a hash of
/// all zeros.
pub fn script_for_address(address: &str) -> Result<Vec<u8>, TxError> {
    let bad = || TxError::Address(address.to_owned());
    if address.get(..3).is_some_and(|start| start.eq_ignore_ascii_case("bc1")) {
        let (hrp, version, program) = bech32::segwit::decode(address).map_err(|_| bad())?;
        if hrp != bech32::hrp::BC {
            return Err(bad());
        }
        let version = version.to_u8();
        if !matches!((version, program.len()), (0, 20 | 32) | (1, 32))
            || program.iter().all(|b| *b == 0)
        {
            return Err(bad());
        }
        let mut script = Vec::with_capacity(2 + program.len());
        // OP_0 for version 0, OP_1 (0x51) for version 1.
        script.push(if version == 0 { 0x00 } else { 0x50 + version });
        script.push(u8::try_from(program.len()).map_err(|_| bad())?);
        script.extend_from_slice(&program);
        return Ok(script);
    }
    let payload = bs58::decode(address).with_check(None).into_vec().map_err(|_| bad())?;
    let (version, hash) = payload.split_first().ok_or_else(bad)?;
    if hash.len() != 20 || hash.iter().all(|b| *b == 0) {
        return Err(bad());
    }
    let mut script = Vec::with_capacity(25);
    match *version {
        P2PKH_VERSION => {
            script.extend_from_slice(&[0x76, 0xa9, 0x14]);
            script.extend_from_slice(hash);
            script.extend_from_slice(&[0x88, 0xac]);
        }
        P2SH_VERSION => {
            script.extend_from_slice(&[0xa9, 0x14]);
            script.extend_from_slice(hash);
            script.push(0x87);
        }
        _ => return Err(bad()),
    }
    Ok(script)
}

/// The key hash of a mainnet P2WPKH address (`bc1q…`, 20 bytes): the only
/// form the wallet spends from, and the only one it sends change to.
pub fn p2wpkh_hash_of_address(address: &str) -> Result<[u8; 20], TxError> {
    p2wpkh_program(&script_for_address(address)?)
        .ok_or_else(|| TxError::Address(address.to_owned()))
}
