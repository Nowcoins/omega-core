//! The wallet's secp256k1 stands on a `crypto-bigint` that has the fix for RUSTSEC-2026-0387:
//! operations meant to be constant-time (subtraction, division, Montgomery multiplication, equality)
//! could branch on secrets. The fix is in `crypto-bigint` 0.7.6 and after, and not in 0.5, which is what
//! `k256` 0.13 uses. So the core names `k256` 0.14 and `bip32` 0.6 (see the root `Cargo.toml`); the 0.13 line
//! is only in the tests, to check signatures independently. This reads `Cargo.lock` and says so if either goes back, and that the
//! README's table of dependencies, which a security review reads, names the versions the lock holds.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;

#[derive(Debug)]
struct Package {
    name: String,
    version: String,
    dependencies: Vec<String>,
}

/// The packages of the workspace's `Cargo.lock`, with each one's dependency entries as written
/// (`"name"`, or `"name version"` when the lock holds more than one version of it).
fn lock() -> Vec<Package> {
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock")).unwrap();
    let mut packages: Vec<Package> = Vec::new();
    let mut listing = false;
    for line in text.lines() {
        if line == "[[package]]" {
            packages.push(Package {
                name: String::new(),
                version: String::new(),
                dependencies: Vec::new(),
            });
            listing = false;
        } else if let Some(package) = packages.last_mut() {
            if let Some(name) = line.strip_prefix("name = ") {
                name.trim_matches('"').clone_into(&mut package.name);
            } else if let Some(version) = line.strip_prefix("version = ") {
                version.trim_matches('"').clone_into(&mut package.version);
            } else if line == "dependencies = [" {
                listing = true;
            } else if line == "]" {
                listing = false;
            } else if listing {
                let entry = line.trim().trim_end_matches(',').trim_matches('"');
                package.dependencies.push(entry.to_owned());
            }
        }
    }
    packages
}

/// The package(s) a dependency entry names.
fn resolve<'a>(packages: &'a [Package], entry: &str) -> Vec<&'a Package> {
    let mut words = entry.split(' ');
    let name = words.next().unwrap();
    let version = words.next();
    packages
        .iter()
        .filter(|p| p.name == name && version.is_none_or(|version| p.version == version))
        .collect()
}

/// What `of` depends on by the name `name`.
fn direct<'a>(packages: &'a [Package], of: &Package, name: &str) -> Vec<&'a Package> {
    of.dependencies
        .iter()
        .flat_map(|entry| resolve(packages, entry))
        .filter(|package| package.name == name)
        .collect()
}

/// Everything `from` depends on, through any number of steps, itself included.
fn reachable<'a>(packages: &'a [Package], from: &'a Package) -> Vec<&'a Package> {
    let mut seen = BTreeSet::new();
    let mut stack = vec![from];
    let mut found = Vec::new();
    while let Some(package) = stack.pop() {
        if seen.insert((&package.name, &package.version)) {
            found.push(package);
            for entry in &package.dependencies {
                stack.extend(resolve(packages, entry));
            }
        }
    }
    found
}

fn numbers(version: &str) -> Vec<u64> {
    version.split('.').map(|part| part.parse().unwrap()).collect()
}

#[test]
fn the_wallets_secp256k1_is_on_a_crypto_bigint_with_the_timing_fix() {
    let packages = lock();
    let core = packages.iter().find(|p| p.name == "nc-wallet-core").unwrap();

    // Its own k256 and its BIP-32 crate's k256 are one and the same package, and it is 0.14.
    let k256 = direct(&packages, core, "k256");
    let bip32 = direct(&packages, core, "bip32");
    assert_eq!(k256.len(), 1, "nc-wallet-core names one k256: {k256:?}");
    assert_eq!(bip32.len(), 1, "nc-wallet-core names one bip32: {bip32:?}");
    assert!(k256[0].version.starts_with("0.14."), "k256 {} is not the 0.14 line", k256[0].version);
    assert!(bip32[0].version.starts_with("0.6."), "bip32 {} is not the 0.6 line", bip32[0].version);
    let under_bip32 = direct(&packages, bip32[0], "k256");
    assert_eq!(under_bip32.len(), 1);
    assert_eq!(under_bip32[0].version, k256[0].version, "bip32 and the core use two k256");

    // Every crypto-bigint under it is 0.7.6 or later.
    let bigints: Vec<_> =
        reachable(&packages, k256[0]).into_iter().filter(|p| p.name == "crypto-bigint").collect();
    assert!(!bigints.is_empty(), "k256 {} reaches no crypto-bigint", k256[0].version);
    for bigint in bigints {
        assert!(
            numbers(&bigint.version) >= vec![0, 7, 6],
            "crypto-bigint {} is under the wallet's k256 and does not have the fix (0.7.6)",
            bigint.version
        );
    }
}

/// The version the README's table of dependencies gives `name`, if the table has a row of its own for it.
fn readme_version(name: &str) -> Option<String> {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md")).unwrap();
    let row = format!("| `{name}` | ");
    text.lines().find_map(|line| {
        let cells = line.strip_prefix(row.as_str())?;
        Some(cells.split(" | ").next()?.trim().to_owned())
    })
}

#[test]
fn the_readme_names_the_versions_of_the_secp256k1_stack_that_the_lock_holds() {
    let packages = lock();
    let core = packages.iter().find(|p| p.name == "nc-wallet-core").unwrap();
    for name in ["bip32", "k256"] {
        let held = direct(&packages, core, name);
        assert_eq!(held.len(), 1, "nc-wallet-core names one {name}: {held:?}");
        assert_eq!(
            readme_version(name).as_deref(),
            Some(held[0].version.as_str()),
            "the README's table of dependencies and Cargo.lock disagree on {name}"
        );
    }
}
