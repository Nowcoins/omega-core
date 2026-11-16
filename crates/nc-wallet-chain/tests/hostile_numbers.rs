//! Every number a node writes may be anything: the answers the apps read, recorded from the live endpoints
//! (`tests/fixtures/live-ops.json`, and the history of each network in `tests/fixtures/history`), are replayed with numbers made hostile, and the operation that asked must
//! come back with an answer or an error and never a panic.
//!
//! In the extension's WebAssembly a panic aborts the whole worker, so no arithmetic on a node's numbers may
//! overflow (`docs/direct-chain.md`). Two places did on one number each (a count of transactions and a
//! block's time), found by doing exactly this; this is what finds the next one without being told where to
//! look. A number is a JSON number, a string of digits, a hex quantity, or one 32-byte word of an ABI answer.
//! It is made the largest the width allows, zero, the next one over, or a negative one.
//!
//! * The test that runs with the others takes each field of each kind of answer in turn and makes it hostile
//!   in every answer of that kind at once (every operator saying the same, as a Bitcoin service that counts
//!   transactions wrongly for every address would), for each operation that reads it.
//! * `cargo test -p nc-wallet-chain --test hostile_numbers -- --ignored` also takes every number of every
//!   answer by itself, so that one operator's lie among honest ones is tried at each place: some fifty
//!   thousand cases, about a minute, and what to run before a release.
//!
//! What it cannot find is a sum or a difference of two numbers that are each fine (a confirmation count, the
//! head of the chain less the block of a coin at block 0): those need two hostile numbers at once, and each
//! of the places found that way has a test of its own (`src/safety_tests.rs`).

#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures::FutureExt;
use nc_wallet_chain::ChainClient;
use nc_wallet_chain::platform::{BoxFut, HttpError, HttpRequest, HttpResponse, Platform};
use nc_wallet_chain::testing::Replay;
use serde_json::{Value, json};

/// The recordings, each with the moment it was made (2026-10-28, 06:31 UTC for the operations the apps make
/// when they open and send, 07:50 for the histories).
const RECORDINGS: [(&str, u64); 6] = [
    (include_str!("fixtures/live-ops.json"), 1_793_171_700_000),
    (include_str!("fixtures/history/bitcoin.json"), 1_793_173_800_000),
    (include_str!("fixtures/history/ethereum.json"), 1_793_173_800_000),
    (include_str!("fixtures/history/solana.json"), 1_793_173_800_000),
    (include_str!("fixtures/history/stellar.json"), 1_793_173_800_000),
    (include_str!("fixtures/history/tron.json"), 1_793_173_800_000),
];
const ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

/// How many ways a number is made hostile.
const WAYS: usize = 4;

// ---- numbers ----

/// Whether `text` is a number written as a string: digits, or a hex quantity of at most 32 bytes.
fn is_number_text(text: &str) -> bool {
    let digits =
        |s: &str, radix| !s.is_empty() && s.len() <= 66 && s.chars().all(|c| c.is_digit(radix));
    digits(text, 10) || text.strip_prefix("0x").is_some_and(|hex| digits(hex, 16))
}

/// Whether `text` is the data of a call: hex, longer than one word and not so long that it is a program.
fn is_word_data(text: &str) -> bool {
    text.strip_prefix("0x").is_some_and(|hex| {
        hex.len() > 66 && hex.len() <= 4_096 && hex.chars().all(|c| c.is_ascii_hexdigit())
    })
}

/// The numbers `value` holds, in order, each as where it is (array positions left out, so that the same
/// field of every record is one place) and what it says.
fn numbers(value: &Value, place: &str, out: &mut Vec<(String, String)>) {
    match value {
        Value::Number(number) => out.push((place.to_owned(), number.to_string())),
        Value::String(text) if is_number_text(text) => out.push((place.to_owned(), text.clone())),
        Value::String(text) if is_word_data(text) => {
            for (at, word) in text.as_bytes()[2..].chunks(64).enumerate() {
                out.push((
                    format!("{place}/word {at}"),
                    String::from_utf8_lossy(word).into_owned(),
                ));
            }
        }
        Value::Array(list) => {
            for item in list {
                numbers(item, &format!("{place}[]"), out);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                numbers(item, &format!("{place}.{key}"), out);
            }
        }
        _ => {}
    }
}

/// Makes number `which` of `value` (counting as [`numbers`] does) hostile in way `way`; says what it was and
/// became. `which` counts down to the number through the parts of `value` that come first.
fn make_hostile(value: &mut Value, which: &mut usize, way: usize) -> Option<String> {
    let hit = |which: &mut usize| {
        if *which == 0 {
            true
        } else {
            *which -= 1;
            false
        }
    };
    match value {
        Value::Number(was) => {
            if !hit(which) {
                return None;
            }
            let now: Value = match way % WAYS {
                0 => json!(u64::MAX),
                1 => json!(0),
                2 => json!(i64::MIN),
                _ => json!(1e30),
            };
            let note = format!("{was} -> {now}");
            *value = now;
            Some(note)
        }
        Value::String(text) if is_number_text(text) => {
            if !hit(which) {
                return None;
            }
            let now = match (text.starts_with("0x"), way % WAYS) {
                (true, 0) => format!("0x{}", "f".repeat(32)),
                (true, 1) => "0x0".to_owned(),
                (true, 2) => format!("0x1{}", "0".repeat(16)),
                (true, _) => format!("0x{}", "f".repeat(64)),
                (false, 0) => u128::MAX.to_string(),
                (false, 1) => "0".to_owned(),
                (false, 2) => "18446744073709551616".to_owned(),
                (false, _) => "-1".to_owned(),
            };
            let note = format!("{text} -> {now}");
            *text = now;
            Some(note)
        }
        Value::String(text) if is_word_data(text) => {
            let words = (text.len() - 2).div_ceil(64);
            if *which >= words {
                *which -= words;
                return None;
            }
            let start = 2 + *which * 64;
            let end = (start + 64).min(text.len());
            let width = end - start;
            let now = match way % WAYS {
                0 => "f".repeat(width),
                1 => "0".repeat(width),
                2 => {
                    let ones = 16.min(width - 1);
                    format!("{}1{}", "0".repeat(width - 1 - ones), "0".repeat(ones))
                }
                _ => format!("{}{}", "0".repeat(width / 2), "f".repeat(width - width / 2)),
            };
            let was = text[start..end].to_owned();
            text.replace_range(start..end, &now);
            Some(format!("word {was} -> {now}"))
        }
        Value::Array(list) => list.iter_mut().find_map(|item| make_hostile(item, which, way)),
        Value::Object(map) => map.values_mut().find_map(|item| make_hostile(item, which, way)),
        _ => None,
    }
}

// ---- the recording, with numbers made hostile ----

/// A recording, and the moment (Unix milliseconds) it was made.
struct Recording {
    replay: Arc<Replay>,
    at: u64,
}

/// What is made hostile.
#[derive(Debug, Clone)]
enum Plan {
    /// The `number`th number of the `answer`th answer given: one operator's lie among honest ones.
    One { answer: usize, number: usize, way: usize },
    /// The number at `place` in every answer to a request of this `kind`: every operator saying the same.
    Field { kind: String, place: String, way: usize },
}

/// The numbers of one answer, and the kind of request it answered.
type Held = (String, Vec<(String, String)>);

/// The recording, answering as it was recorded except for what the plan makes hostile, on a clock of its own
/// (a pause moves it and nothing else's) that starts at the moment of the recording.
struct Hostile {
    inner: Arc<Replay>,
    clock: AtomicU64,
    plan: Option<Plan>,
    given: AtomicUsize,
    /// The answers given, in order.
    answers: Mutex<Vec<Held>>,
    /// What was made hostile.
    done: Mutex<Option<String>>,
}

impl Hostile {
    fn new(recording: &Recording, plan: Option<Plan>) -> Arc<Self> {
        Arc::new(Self {
            inner: recording.replay.clone(),
            clock: AtomicU64::new(recording.at),
            plan,
            given: AtomicUsize::new(0),
            answers: Mutex::new(Vec::new()),
            done: Mutex::new(None),
        })
    }
}

/// What a request asks, without the address or the hash it asks it of: its JSON-RPC method (and, for a
/// call, the function), or its path with the long names left out.
fn kind_of(request: &HttpRequest) -> String {
    let body = request.body.as_deref().map(|b| String::from_utf8_lossy(b).into_owned());
    let asked = body.as_deref().and_then(|b| serde_json::from_str::<Value>(b).ok());
    if let Some(method) = asked.as_ref().and_then(|b| b["method"].as_str()) {
        let data = asked.as_ref().and_then(|b| b["params"][0]["data"].as_str());
        let function = data.map(|d| d.chars().take(10).collect::<String>());
        return format!("{method} {}", function.unwrap_or_default());
    }
    let path: Vec<&str> =
        request.url.split('/').skip(3).map(|s| if s.len() > 20 { "*" } else { s }).collect();
    format!("{:?} {}", request.method, path.join("/"))
}

impl Platform for Hostile {
    fn send(&self, request: HttpRequest) -> BoxFut<'_, Result<HttpResponse, HttpError>> {
        Box::pin(async move {
            let kind = kind_of(&request);
            let mut response = self.inner.send(request).await?;
            let answer = self.given.fetch_add(1, Ordering::Relaxed);
            let Ok(mut body) = serde_json::from_slice::<Value>(&response.body) else {
                self.answers.lock().unwrap().push((kind, Vec::new()));
                return Ok(response);
            };
            let mut held = Vec::new();
            numbers(&body, "", &mut held);
            let mut made: Vec<String> = Vec::new();
            match &self.plan {
                Some(Plan::One { answer: at, number, way }) if *at == answer => {
                    made.extend(make_hostile(&mut body, &mut number.clone(), *way));
                }
                Some(Plan::Field { kind: wanted, place, way }) if *wanted == kind => {
                    // (A number made hostile keeps its place, so the others are where they were.)
                    for (number, (found, _)) in held.iter().enumerate() {
                        if found == place {
                            made.extend(make_hostile(&mut body, &mut number.clone(), *way));
                        }
                    }
                }
                _ => {}
            }
            if !made.is_empty() {
                *self.done.lock().unwrap() = Some(made.join(", "));
                response.body = body.to_string().into_bytes();
            }
            self.answers.lock().unwrap().push((kind, held));
            Ok(response)
        })
    }

    fn sleep(&self, millis: u64) -> BoxFut<'_, ()> {
        Box::pin(async move {
            self.clock.fetch_add(millis, Ordering::Relaxed);
        })
    }

    fn now_ms(&self) -> u64 {
        self.clock.load(Ordering::Relaxed)
    }
}

// ---- what the apps ask ----

/// Something the apps ask, and the recording that answers it.
struct Operation {
    label: String,
    op: &'static str,
    request: Value,
    recording: usize,
}

impl Operation {
    fn new(label: String, op: &'static str, request: Value, recording: usize) -> Self {
        Self { label, op, request, recording }
    }
}

/// What the apps ask when they open and when they send, for the wallets the recording was made for.
fn operations() -> Vec<Operation> {
    const FRIEND: &str = "0x5BC24606e389465DF34068fCC3357465e7A473C2";
    let wallets = [
        ("ethereum", "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", FRIEND, "USDT"),
        ("bsc", "0x8894E0a0c962CB723c1976a4421c95949bE2D4E3", FRIEND, "BNB"),
        ("polygon", "0xe7804c37c13166fF0b37F5aE0BB07A3aEbb6e245", FRIEND, "POL"),
        ("base", "0x4200000000000000000000000000000000000016", FRIEND, "ETH"),
        (
            "tron",
            "TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9",
            "TWd4WrZ9wn84f5x1hZhL4DHvk738ns5jwb",
            "USDT",
        ),
        (
            "bitcoin",
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            "bc1qg3f7exyzcgpw48ysh58rgpuu7vyh9wnu64mae8",
            "BTC",
        ),
        (
            "solana",
            "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9",
            "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
            "USDC",
        ),
        (
            "stellar",
            "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
            "GBDEVU63Y6NTHJQQZIKVTC23NWLQVP3WJ2RI2OTSJTNYOIGICST6DUXR",
            "XLM",
        ),
        (
            "bittensor",
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
            "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",
            "TAO",
        ),
    ];
    let mut out = vec![Operation::new("prices".to_owned(), "prices", json!({}), 0)];
    for (id, address, to, asset) in wallets {
        let mut balances = json!({ "network": id, "address": address });
        let mut inputs = json!({ "network": id, "address": address });
        let mut estimate =
            json!({ "network": id, "from": address, "to": to, "asset": asset, "amount": "1000" });
        if id == "bitcoin" {
            for request in [&mut balances, &mut inputs, &mut estimate] {
                request["zpub"] = json!(ZPUB);
            }
            estimate["amount"] = json!("10000");
        }
        if ["ethereum", "bsc", "polygon", "base"].contains(&id) {
            estimate["tiers"] = json!(true);
        }
        out.push(Operation::new(format!("balances {id}"), "balances", balances, 0));
        out.push(Operation::new(format!("inputs {id}"), "inputs", inputs, 0));
        out.push(Operation::new(format!("estimate {id}"), "estimate", estimate, 0));
    }
    for (id, hash) in [
        ("ethereum", "0x316a268da99f8a8e28c851548d3f20080e8f030e8c15811bf161dd32fc43db5f"),
        ("tron", "6150b2bb0a8871c7607d63e5cfdee96887bdd90cb49789cf5f790fc07c1c5ba5"),
        ("stellar", "a2854a78247bd08a425cf79254654488f7f56be4136f274494cf82f515bd0544"),
        (
            "solana",
            "2LPEaTFDLJPQ8KtwwEZotJS5deGmtc5Wif4Rc3ymowd78KmLpQ9rDiJ1xkYZ9AyXxjnWhz6UEUqAS4BV7E8UYrJd",
        ),
    ] {
        let request = json!({ "network": id, "hash": hash });
        out.push(Operation::new(format!("status {id}"), "status", request, 0));
    }
    // The histories, over the recordings made for each (the addresses are theirs).
    for (recording, request) in [
        (
            1,
            json!({ "network": "bitcoin", "address": "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g" }),
        ),
        (
            2,
            json!({ "network": "ethereum", "address": "0xdee6a6d5f1e0af9364fc247f034b5508080a268a",
                    "limit": 50, "balance": "1000000000" }),
        ),
        (
            3,
            json!({ "network": "solana", "address": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM" }),
        ),
        (
            4,
            json!({ "network": "stellar",
                    "address": "GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H" }),
        ),
        (5, json!({ "network": "tron", "address": "TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9" })),
    ] {
        let label = format!("history {}", request["network"].as_str().unwrap_or_default());
        out.push(Operation::new(label, "history", request, recording));
    }
    out
}

/// Runs `op` on a client of its own over `platform`, the way the apps do; a panic comes back as its message.
fn run(platform: &Arc<Hostile>, op: &str, request: &Value) -> Result<(), String> {
    let client = ChainClient::new(platform.clone());
    let asked = AssertUnwindSafe(async {
        let _ = client.call(op, &request.to_string()).await;
    });
    futures::executor::block_on(asked.catch_unwind()).map_err(|panic| {
        panic
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "a panic".to_owned())
    })
}

// ---- the sweeps ----

/// What a sweep did.
#[derive(Default)]
struct Swept {
    cases: usize,
    /// Each panic, with the first thing that caused it.
    panics: BTreeMap<String, String>,
}

/// Every operation once as recorded: the answers it takes, of what kind, and the numbers each holds.
fn recorded(recordings: &[Recording], operations: &[Operation]) -> Vec<Vec<Held>> {
    operations
        .iter()
        .map(|operation| {
            let first = Hostile::new(&recordings[operation.recording], None);
            run(&first, operation.op, &operation.request)
                .unwrap_or_else(|panic| panic!("{} as recorded: {panic}", operation.label));
            first.answers.lock().unwrap().clone()
        })
        .collect()
}

/// Makes the numbers of `operation`, whose recorded answers are `answers`, hostile: each field of each kind of
/// answer it reads in all of them at once, and, if `every_number`, each number by itself.
fn sweep_operation(
    operation: &Operation,
    answers: &[Held],
    recording: &Recording,
    every_number: bool,
    swept: &mut Swept,
) {
    let mut try_plan = |plan: Plan, what: &str| {
        let platform = Hostile::new(recording, Some(plan));
        swept.cases += 1;
        if let Err(panic) = run(&platform, operation.op, &operation.request) {
            let made = platform.done.lock().unwrap().clone().unwrap_or_default();
            swept
                .panics
                .entry(panic)
                .or_insert_with(|| format!("{}, {what}: {made}", operation.label));
        }
    };
    let fields: BTreeSet<(&String, &String)> = answers
        .iter()
        .flat_map(|(kind, numbers)| numbers.iter().map(move |(place, _)| (kind, place)))
        .collect();
    for (kind, place) in fields {
        for way in 0..WAYS {
            let plan = Plan::Field { kind: kind.clone(), place: place.clone(), way };
            try_plan(plan, &format!("{kind}, {place}, in every answer"));
        }
    }
    if every_number {
        for (answer, (kind, numbers)) in answers.iter().enumerate() {
            for (number, (place, _)) in numbers.iter().enumerate() {
                for way in 0..WAYS {
                    let plan = Plan::One { answer, number, way };
                    try_plan(plan, &format!("{kind}, {place}, in answer {answer}"));
                }
            }
        }
    }
}

fn sweep(every_number: bool) -> Swept {
    let recordings: Vec<Recording> = RECORDINGS
        .iter()
        .map(|(text, at)| Recording { replay: Arc::new(Replay::new(text, *at)), at: *at })
        .collect();
    let operations = operations();
    let held = recorded(&recordings, &operations);
    // The cases do not depend on each other: the operations are shared out among a few threads, the biggest
    // first.
    let mut jobs: Vec<(&Operation, &Vec<Held>)> = operations.iter().zip(&held).collect();
    jobs.sort_by_key(|(_, answers)| {
        std::cmp::Reverse(answers.iter().map(|a| a.1.len()).sum::<usize>())
    });
    let next = AtomicUsize::new(0);
    let threads = std::thread::available_parallelism().map_or(1, usize::from).min(4);
    let parts: Vec<Swept> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(|| {
                    let mut mine = Swept::default();
                    while let Some((operation, answers)) =
                        jobs.get(next.fetch_add(1, Ordering::Relaxed))
                    {
                        let recording = &recordings[operation.recording];
                        sweep_operation(operation, answers, recording, every_number, &mut mine);
                    }
                    mine
                })
            })
            .collect();
        workers.into_iter().map(|worker| worker.join().unwrap()).collect()
    });
    let mut swept = Swept::default();
    for part in parts {
        swept.cases += part.cases;
        for (panic, how) in part.panics {
            swept.panics.entry(panic).or_insert(how);
        }
    }
    swept
}

fn assert_none_panicked(swept: &Swept) {
    assert!(swept.cases > 500, "{} cases is not a sweep", swept.cases);
    assert!(
        swept.panics.is_empty(),
        "a node's numbers made the client panic ({} cases):\n{}",
        swept.cases,
        swept
            .panics
            .iter()
            .map(|(panic, how)| format!("  {panic}\n    caused by {how}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn each_field_of_each_kind_of_recorded_answer_made_hostile_in_all_of_them_never_panics_the_client()
{
    let swept = sweep(false);
    println!("{} cases", swept.cases);
    assert_none_panicked(&swept);
}

#[test]
#[ignore = "every number of every answer by itself, about a minute: run before a release"]
fn every_number_of_every_recorded_answer_made_hostile_by_itself_never_panics_the_client() {
    let swept = sweep(true);
    println!("{} cases", swept.cases);
    assert_none_panicked(&swept);
}
