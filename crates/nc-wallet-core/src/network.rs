//! The networks the wallet derives accounts for.

/// A family of chains that share one key and one address format.
///
/// `Evm` stands for Ethereum, BNB Chain, Polygon, Base and every other EVM
/// chain: one key, one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    /// Ethereum and the EVM chains: secp256k1, EIP-55 `0x…`.
    Evm,
    /// TRON: secp256k1, base58check `T…`.
    Tron,
    /// Bitcoin: secp256k1, native segwit P2WPKH `bc1q…`.
    Bitcoin,
    /// Solana: ed25519 by SLIP-10, base58.
    Solana,
    /// Stellar: ed25519 by SLIP-10 (SEP-0005), strkey `G…`.
    Stellar,
    /// Bittensor: sr25519 by Substrate's derivation, SS58 with prefix 42.
    Bittensor,
}

impl Network {
    /// Every network, in the order the wallet lists them.
    pub const ALL: [Self; 6] =
        [Self::Evm, Self::Tron, Self::Bitcoin, Self::Solana, Self::Stellar, Self::Bittensor];

    /// The derivation path of account `index`, as the wallets that share the
    /// phrase write it:
    ///
    /// | Network | Path |
    /// |---|---|
    /// | `Evm` | `m/44'/60'/0'/0/{index}` |
    /// | `Tron` | `m/44'/195'/0'/0/{index}` |
    /// | `Bitcoin` | `m/84'/0'/{index}'/0/0` (BIP-84 account `index`: its receive chain `/0/n` and change chain `/1/n`) |
    /// | `Solana` | `m/44'/501'/{index}'/0'` (Phantom's; Trust Wallet's is `m/44'/501'/0'`, see [`crate::solana::TRUST_WALLET_PATH`]) |
    /// | `Stellar` | `m/44'/148'/{index}'` |
    /// | `Bittensor` | none for index 0, the phrase's root key; `//{index}` after |
    ///
    /// The Bittensor value is a Substrate junction, to be read after the
    /// phrase (`<phrase>//1`), not a BIP-32 path.
    pub fn derivation_path(self, index: u32) -> String {
        match self {
            Self::Evm => format!("m/44'/60'/0'/0/{index}"),
            Self::Tron => format!("m/44'/195'/0'/0/{index}"),
            Self::Bitcoin => format!("m/84'/0'/{index}'/0/0"),
            Self::Solana => format!("m/44'/501'/{index}'/0'"),
            Self::Stellar => format!("m/44'/148'/{index}'"),
            Self::Bittensor if index == 0 => String::new(),
            Self::Bittensor => format!("//{index}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_the_plans() {
        // The paths in the README's table of networks.
        assert_eq!(Network::Evm.derivation_path(3), "m/44'/60'/0'/0/3");
        assert_eq!(Network::Tron.derivation_path(3), "m/44'/195'/0'/0/3");
        assert_eq!(Network::Bitcoin.derivation_path(3), "m/84'/0'/3'/0/0");
        assert_eq!(Network::Solana.derivation_path(3), "m/44'/501'/3'/0'");
        assert_eq!(Network::Stellar.derivation_path(3), "m/44'/148'/3'");
        assert_eq!(Network::Bittensor.derivation_path(0), "");
        assert_eq!(Network::Bittensor.derivation_path(3), "//3");
        assert_eq!(Network::ALL.len(), 6);
    }
}
