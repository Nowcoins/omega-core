//! Prints the endpoints' origins as a browser extension's `chain-origins.json`:
//!
//!     cargo run -q -p nc-wallet-chain --example origins > chain-origins.json
//!
//! `origins` is the extension's `host_permissions` (a match pattern for each endpoint's origin, once
//! each); `hosts` names the hosts of each network, for the tests' fake chain.
//!
//! With `--urls` it prints instead every endpoint's address by network (name, url, operator, pace),
//! for `scripts/endpoint_check.py`.

fn main() {
    if std::env::args().any(|a| a == "--urls") {
        let mut out = serde_json::Map::new();
        for network in nc_wallet_chain::networks::ALL {
            let list: Vec<serde_json::Value> = nc_wallet_chain::endpoints::specs(network)
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "name": s.name, "url": s.url, "operator": s.operator, "per_second": s.per_second,
                    })
                })
                .collect();
            out.insert(network.id().to_owned(), serde_json::Value::Array(list));
        }
        println!("{}", serde_json::Value::Object(out));
        return;
    }
    // The text already ends in a newline.
    print!("{}", nc_wallet_chain::endpoints::origins_json());
}
