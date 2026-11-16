# Nowcoin Omega reads the networks itself

For the self-custody wallet there is **no backend**. Nowcoin stores no balance, takes nothing, and sees nothing: the
Android app and the Chrome extension read balances, the coins to spend, the network fees, prices and history, and
broadcast transactions, by calling **public blockchain endpoints directly from the user's device**. This replaced an
earlier wallet API, whose server was deleted; the chain client answers in the shapes it did
(`crates/nc-wallet-chain/tests/fixtures/wallet-api/`).

Hard rules, kept by tests where a test can keep them: no API key of any kind; no indexer or explorer API (no Blockscout,
Etherscan, Taostats, Covalent, Moralis, Alchemy, Infura or the like); no price API; a bot challenge is never gone round;
nothing about a user reaches a Nowcoin server (there is none to reach).

* The code is `crates/nc-wallet-chain`, **one Rust implementation** for both apps: the Android app reaches it through
  `nc-wallet-ffi` (reqwest over rustls, with bundled roots), the extension's service worker through `nc-wallet-wasm` (the
  browser's `fetch`, lent by the extension).
* **Independence, kept by tests.** Nowcoin Omega never talks to a Nowcoin server: no endpoint of the list is a Nowcoin host
  (`nc-wallet-chain`'s `no_endpoint_host_is_a_nowcoin_host`), and the apps' own tests check that neither makes a request to
  any Nowcoin host. Their Buy and Exchange buttons are plain links that open nowcoin.xyz in the browser; nothing is sent
  with them.
* It has no keys and no secrets. It reads, and hands the signing engine the numbers a transaction is built from, in the
  shapes the apps and `nc-wallet-session`'s `send` request already read.
* History is its own document: [`history.md`](history.md).

## Sources, by network

| Network | Read from | What for |
|---|---|---|
| Ethereum, BNB Chain, Polygon, Base | JSON-RPC of public nodes (PublicNode, dRPC, MeowRPC, BlockRazor, BNB Chain's dataseeds, Tenderly's gateway, Coinbase's Base node, ...) | balances in **one `eth_call` of Multicall3** (the coin through `getEthBalance`, each token through `balanceOf`); the nonce (`pending`); the fee market (`eth_feeHistory`, `eth_maxPriorityFeePerGas`); `eth_estimateGas`; Base's L1 data fee from its gas price oracle; `eth_sendRawTransaction`; receipts |
| TRON | the nodes' HTTP API (`/wallet/*`: PublicNode, TronGrid keyless, Pocket) and their Ethereum-compatible `/jsonrpc` | balances through `/jsonrpc` (`eth_getBalance`, `eth_call`: 150 bytes, where `getaccount` is 18 KB); reference block (`getblock`, header only), prices (`getchainparameters`), resources, constant calls for a token's energy; `broadcasthex` |
| Bitcoin | **Esplora**: mempool.space, with Blockstream's as the backup | `/address/{a}` (balance with the mempool, and whether an address was ever used), `/address/{a}/utxo`, `/fee-estimates`, `/blocks/tip/height`, `POST /tx`; for the **whole BIP-84 account** (below) |
| Solana | JSON-RPC of public nodes (PublicNode, Pocket Network's gateway; the Foundation's too, on the Android app only) | `getBalance`, token accounts (`getTokenAccountsByOwner`, or the owner's associated accounts in one `getMultipleAccounts` where the indexed call is refused), `getLatestBlockhash`, `getRecentPrioritizationFees`, `getAccountInfo`, rent, `sendTransaction` |
| Stellar | **Horizon**: the SDF's, LOBSTR's, Ankr's | `/accounts/{id}`, `/fee_stats`, `/ledgers`, `POST /transactions` (a muxed `M…` destination, SEP-23, is asked about by the account behind it and paid as the muxed account it is) |
| Bittensor | Finney nodes (Opentensor's three, OnFinality's) | `System.Account` storage, the nonce, the runtime's version and **metadata**, the fee quote (`TransactionPaymentApi_query_info`), `author_submitExtrinsic` |

The Bittensor runtime is checked against its metadata (the Balances pallet and the call's indexes, the transaction
extensions in order and their shapes, the account layout, the existential deposit) before anything is built for it, as the
server did: a runtime that does not pass answers `upstream_unavailable` and **nothing is guessed**. The metadata is some
700 KB of hex, read once per runtime version and remembered (the client's small memory keeps which versions passed).

## The endpoint list

Bundled in the client (`src/endpoints.rs`), one list per network; the extension's `host_permissions` are **generated from
it** (`src/data/chain-origins.json`, 35 origins) and a test fails when the two drift. Each entry has a pace under the
endpoint's published rate (or less where none is published), a weight, an operator, and what it refuses (the BNB Chain
dataseeds refuse `eth_getLogs`; PublicNode's Base refuses receipts; Pocket's TRON gateway refuses constant calls, which size a
token transfer; Tenderly's gateway and MEV Blocker serve logs far back).

* **Rotation and failover.** Endpoints that may be used right now share the work in proportion to their weights (smooth
  weighted round robin). A request that fails, is rate-limited, or answers in a shape the endpoint does not document goes to
  another endpoint.
* **Pacing on the device.** A limiter per endpoint (GCRA on the platform's clock); a request that would wait too long goes
  elsewhere; if all are resting the answer is `upstream_busy` with a time.
* **Health.** Three failures in a row rest an endpoint (30 s, doubling to five minutes); a `429` is waited out; a method an
  endpoint does not serve is not asked of it again for ten minutes; an endpoint behind a **bot challenge** is left alone for
  five minutes and never worked around. An answer that says "needs a personal token" is the endpoint's problem, not a verdict.
* **No single operator is trusted for a figure that moves money** (next section).
* **Broadcast to more than one endpoint** at once (EVM three, Solana two, TRON two, Stellar two, Bitcoin both Esplora
  services, Bittensor three). One acceptance is a success; "already known" next to it is the first endpoint's work reaching
  the second; a refusal is told in the words of the network (`insufficient_fee`, `nonce`, `duplicate`, ...).
* **What teaches the pool, and what does not.** A node's *words* never describe a contract: a revert (code 3, "execution
  reverted", or revert data) is the contract's verdict and its reason reaches the caller, whatever it says ("transfers not
  allowed", "disabled", "rate limit"); `eth_call` and `eth_estimateGas` are taken off an endpoint only by a plain "no such
  method" (or `-32601`). A web page's request is passed through with `Caller::Site`: it teaches the pool only through the
  error *codes* a node chose and through the transport, never through words a page could make a node echo. A page cannot
  switch a method off for the wallet's own reads. The one answer in words that does take a method off is a TRON node saying
  it is run without constant calls (`CONTRACT_VALIDATE_ERROR`, "this node does not support constant", with no energy in the
  answer): that is the node's own limit and no contract's, so the next operator is asked and the node is not asked again for
  ten minutes. A contract that is not there, or a revert, is the call's and is handed back.

## The Bitcoin account

An account is a whole BIP-84 account, `m/84'/0'/N'`, not one address: Esplora has no query for an account, so the client derives
the addresses from the account's **`zpub`** (a public key; the apps get it from the engine and no private key leaves it) and
asks about each, as every wallet does. The address shown to receive is receive index 0 (`/0/0`); a wallet restored from a
phrase may have used any receive address (`/0/n`) or change address (`/1/n`) of the account, and all of them count:

* **Balance, history and sending** use every address of the account. A payment is signed by the key of each coin's own address
  (the engine derives it from the seed, by chain and index) and its change goes to the next **unused** change address (never
  back to a used one).
* **The walk** ends on each chain at 20 unused addresses in a row (the gap limit). A reading makes at most 200 lookups or 12
  seconds, then hands back where it stopped (`scanning`, a `resume` point in the *hint*) and the app asks again; a reading
  that is not finished is not cached.
* **The hint** is what a reading leaves: the highest used index on each chain and which addresses hold coins. The app keeps it
  (Android: a sealed file; the extension: sealed in `chrome.storage.local`, like a history) and hands it back, so the next reading asks
  only about the live addresses, receive 0 and the few past the highest used. A wallet **created here** is given a hint with nothing used.
* **Cost**, measured over the recordings of the live endpoints: a new wallet's first reading is 5 requests; a restored account
  of 42 used receive addresses takes 2 readings and 95 requests the first time (62 receive and 21 change lookups, and the
  unspent outputs of the live ones), then 6 requests a reading with its hint. A full re-check of every used address is made when
  the hint is a day old.
* **One service's word is not enough to forget coins or to move the change.** An address the hint held coins at that a
  lookup now says is empty is asked of a second operator before it is dropped (found with coins: kept; both say empty: it
  was spent; the second cannot be asked: kept as it was and asked again next time), so a lagging or lying service cannot hide
  coins from the balance and the next payment for a day. The change goes to the address after the highest *change* address that
  two operators agree is used (checked once, when a finished reading finds a new highest): a service that says change 5,000 is used
  cannot push the change past every other wallet's gap of 20, where a restore could not find it (the coins it claims are still
  shown; only where the change goes is held to two opinions). A hint dated in the future is read in full, like one a day old.
* **Unconfirmed money** is spent only if it is this wallet's own change that this device sent (`own` on the output, from the record
  of sends); a transaction from outside can be replaced before it is mined and the payment would fail.
* **The fee shown is the fee signed.** The estimate does not choose coins of its own: for each speed it asks the rule the
  signing engine's planner lays the payment out by (`nc_wallet_core::bitcoin::quote`: the largest coins first, change kept only
  when it is worth an output, any number of coins that leaves that much preferred, the rest given to the fee), over the same
  coins. A coin that holds nothing is left out, and one that holds more than there is bitcoin makes the list no answer of
  Esplora's.
* **Not found:** a used address beyond a gap of 20 (the same as every wallet's).

## Figures that move money

An endpoint is only ever believed *within bounds the wallet itself holds*.

* **An operator is an organisation**, not a host (PublicNode's two Ethereum hosts, or BNB Chain's three dataseeds, are one
  opinion). For a figure, `Need::independent` makes this a rule and not a preference: an operator already heard is never
  asked again for the same figure, and a failed endpoint's operator is still a candidate through another host.
* **Two operators agree, or the figure is not used** (`quorum.rs`): fees within a quarter of each other (the higher is
  used); Bitcoin's rates, which two services estimate differently, within a factor of three plus 2 sat/vB (the higher); a
  nonce only when equal. Where they differ a third is asked and a figure two agree on wins, so one liar, high or low, is
  outvoted. A nonce is never taken from the lower of two disagreeing sources (it would replace the person's own pending
  transaction) nor from the higher (a gap): the answer is "could not be confirmed, try again".
* **Two bounds per figure, in `nc_wallet_core::limits`**, the same for both apps:
  *alone* is the most a lone operator's figure may be (above it a second must agree, else "the network fee could not be
  confirmed, try again"); *refuse* is the most that is ever used, however many agree (above it the answer is "above the most
  this wallet will pay": refused, never clamped). The signing code checks *refuse* again on the transaction it is about to
  sign (`FeeTooHigh`), including a web page's EVM transaction rates.

| Figure | alone | refuse | Notes |
|---|---|---|---|
| Ethereum max fee per unit / tip | 150 / 20 gwei | 1,000 / 200 gwei | a send also: 600,000 units of work at most, 0.01 ETH alone, 0.05 ETH reserved at most |
| BNB Chain | 20 / 5 gwei | 200 / 50 gwei | 0.01 / 0.05 BNB |
| Polygon | 1,000 / 500 gwei | 10,000 / 10,000 gwei | real transactions have paid 5,000; 5 / 20 POL |
| Base | 5 / 2 gwei | 200 / 50 gwei | layer-1 data fee 0.0005 / 0.005 ETH, read from two operators; 0.001 / 0.005 ETH in all |
| Bitcoin fee rate | 100 sat/vB | 1,000 sat/vB | and 0.01 BTC for one payment. A service quoting past 1,000 is set aside as if it had not answered |
| Solana fee in all | 0.001 SOL | 0.01 SOL | the priority fee is also clamped by the wallet to at most 1,000,000 micro-lamports a unit, from two operators |
| TRON fee limit | 100 TRX | 300 TRX | energy price 500 / 2,000 sun, bandwidth 1,500 / 5,000 sun, from two operators |
| Stellar base fee | 0.001 XLM | 0.1 XLM | an operation, from two operators |
| Bittensor transfer fee | 0.001 TAO | 0.01 TAO | what the person is shown; the chain charges its own. The tip is always 0 |

* **Speeds.** Bitcoin offers slow, standard and fast (12, 3 and 1 blocks). So does the estimate of an EVM network, when the
  request says `"tiers": true` (`fees.slow`, `fees.normal`, `fees.fast`; standard is also the top of the answer, and is all
  that an estimate without the ask holds, at no cost in requests): slow leaves room for one block's rise of an eighth and tips
  what the quiet blocks of the last ten paid, fast keeps standard's two blocks of room and tips what the busy ones paid (the
  10th and 90th percentile of each block's tips, from `eth_feeHistory` asked of two operators). A speed they cannot vouch for,
  or whose bid or total is past the bounds above, is `null` and not offered. BNB Chain is offered speeds too: its blocks carry
  a base fee, and it is 0 (checked live on 2026-11-02: `baseFeePerGas` of `0x0`, a node tip of 0.05 gwei), so a bid is its tip
  alone, slow cannot go under the 0.05 gwei the network asks and so is standard, and fast differs by what the busy blocks
  tipped (about 0.07 gwei at the 90th percentile). The engine prices a send at `options.fee_speed` only where the estimate
  offers speeds: the tier of that name, held to the same ceilings (`FeeTooHigh`), and a tier the
  estimate left out is `BadRequest`. An estimate without `fees` has one price, and a `fee_speed` in the request changes nothing:
  the apps keep the speed chosen for Bitcoin in the send form and send it with a send on any network. TRON, Solana, Stellar and
  Bittensor have one fee (the chain sets it; there is no market for speed), so they offer no speeds.
* **Nonces** (EVM, Bittensor) must be confirmed by two operators and are never below *one past the last this device sent*
  while that record is fresh (`sent.rs`: the apps pass `from` and `nonce` with a broadcast; ten minutes; wiped
  with the wallet). The record is the client's memory, so it is **kept across a restart of the app**: the Android app seals it
  (AES-256-GCM under the wallet's key, like a history) into a file after every send and takes it back before it builds the next
  transfer; the extension keeps it in `chrome.storage.session`, which survives the service worker being stopped after about 30 s of
  idle. Lost anyway, it only means the number is taken from what two operators agree on, which can lag for a few seconds after a
  send. **A transaction that is dropped** (never mined) leaves its number free again after ten minutes; until then a later
  transfer waits behind a gap (the nodes keep it pending) and the person can send again once the record has lapsed. A retry the nodes call "nonce used" is "already sent" where this device had it accepted, or where any
  of three operators has the transaction or its receipt by hash.
* **The fee is shown in dollars, and a high one needs an extra OK** (both apps, one table): the person must tick "I accept
  this network fee of $X" before the hold sends when the signer warned (`high_fee`); the fee is more than $5.00; the fee is
  more than 5% of the amount sent *and* more than $0.50; or, where a coin has no price, the fee is more than 20% of the
  amount in the same coin. Every limit is strict. Prices only advise: the bounds above are in coin units and do not depend
  on a price, and a price that is absent or zero is never read as "free" (it would turn any fee into nothing).
* **The engine holds the tick too**, below the screens: it raises `fee_high` when a fee is above the *alone* line of its
  network in the coin itself (so a token send, or a coin with no price, is covered), and `high_fee` when it is a large part
  of the amount. It **refuses to sign** either (`FeeNotAccepted`) unless the request carries `fee_ok: true`, which the apps
  add only after the person ticks. `fee_ok` is not part of what is approved: the approval hash is the same with or without it.
  A fee over the *refuse* line is refused whatever is ticked (`FeeTooHigh`).
* **A web page's transaction** (extension only) is bound the same way, with its own bounds: an EVM call may reserve at most
  3,000,000 units of work (a heavy swap or bridge uses up to about two million) and a total fee of ten times a plain send's
  (0.05 / 0.5 ETH alone / refuse); a Solana priority fee is held to the wallet's cap. The work is asked of two operators
  (`gas`): the higher figure is given with how many stand behind it (answers within a quarter of the highest). With two, a figure the
  page names is cut to twice the estimate plus 50,000; with one answer, or two that disagree, the estimate never raises the bound: the
  page's figure is used as named up to the 3,000,000 cap, and with none named the estimate plus a fifth, never above the cap. The
  figure the person approves is the bound that is signed. Its approval shows the fee in dollars and asks for the same tick.
* **Only one source for a total** is held to the lower *alone* line: a total that rests on a single operator may not exceed it
  (EVM, Solana, Bitcoin), only a figure two operators agree on may reach *refuse*. Bitcoin's rates are judged **per target**
  (a "fast" quote above 1,000 sat/vB is set aside for that target and the slower ones still show), a tip is compared after the
  minimum tip is applied and within a gwei, and Stellar is not built at all when the network's own ledger time cannot be read
  (the device's clock is never a substitute).

**What may come from one source, and why.** A figure may rest on one operator when the worst a liar can do is a failed send,
never a loss:

| From one operator | Why it is safe |
|---|---|
| Bitcoin's unspent outputs and their values | a segwit signature commits to each input's amount: a lie makes an invalid transaction the network refuses |
| Solana's blockhash, TRON's reference block, Stellar's sequence, Bittensor's head, runtime versions and genesis | a wrong one makes a transaction the chain refuses or that expires; the signature binds the rest |
| EVM chain id, token contracts, Multicall3, Chainlink feeds | pinned in the wallet (feeds' addresses, descriptions and decimals included) |
| Balances and prices | they only inform; no amount moves because of them |
| A web page's `eth_estimateGas`, simulations | the person sees the result in the approval, within the same per-unit bounds |

A Solana transaction's lookup tables are the exception that is not harmless to read from one node (the summary shows what
the table says), so they are read from two operators that must agree byte for byte (`solana_tables`); otherwise the
approval says "the destination of this transaction could not be verified" and nothing is summarised or signed.
Stellar's time bounds come from the network's latest ledger, not the device's clock.

## What a lone operator cannot make true

* **A receipt** (`status`): `confirmed` or `failed` only when a second, independent operator gives the same receipt (outcome and block);
  otherwise `status: "pending"` with `unverified: true` and `reported`. A not-found is checked against a second operator before it is said.
  A transaction costs one extra request, once, when its first receipt arrives.
* **A broadcast** answered "already known" with nobody accepting it is a success only if this device had it accepted or another
  operator has it by hash; otherwise it is `estimate_failed` with `reason: "unconfirmed"` (retryable, and not shown as sent).
* **Hints that guard a payment**: a Stellar destination needs a memo if either of two operators says so; a Solana
  destination is a token account if either of two says so, and a SOL transfer's destination is a program's account (a mint, a
  token account, a program, a sysvar: `recipient.program_owned`, which the engine turns into the warning
  `recipient_is_program_account`) if either of two says a program other than the System Program owns it. Others rest on one operator, and the worst a lie does is a failed send
  or a fee shown a little too high (`trustline`, `exists`, TRON `activated`, Bittensor `exists`).
* **TRON's block time** rides into the transaction's timestamp and expiry, so a node that said it was a day ahead would make
  a transaction that lives a day. The latest block is asked of two operators whose times must be within five minutes of each
  other (a third is asked where they are not), and the **earlier** is the time the transaction expires from: two that are
  close cannot tell which of them is wrong, and counting from the later would let one that is five minutes ahead make a
  transaction signed for a minute live for nearly six. (The time is never earlier than the device's own clock, which covers a
  node that is behind.) One operator alone is believed only if it is not ahead of the device's clock by more than five
  minutes. Where two agree the device's clock is not the judge, so a phone days behind still builds. A time past the year 9999
  is not a block's.
* **A Bittensor send** has no receipt to ask for (the nodes keep no index of extrinsics): the history settles it by the account's
  nonce on chain from two operators, and never by a timer (`docs/history.md`). A "confirmed" send there means
  *included*; whether its transfer worked is shown by the balance alone.
* **Bittensor** is built with its genesis hash and `Balances.transfer_keep_alive` (pallet 5, call 3) pinned in the signing engine; inputs that name
  others are refused (`Unsupported`).
* **A node's own words** are not passed on. A refusal is told by its code with fixed wording; a contract's revert reason is quoted as what the
  network reports; a result code shows only if it looks like one. The HTTPS client has no fallback: if it cannot be built every request fails.

## What the nodes write is never trusted to fit

Every number a service or node writes is read as something that may be anything. Amounts are parsed within bounds
(a token amount is at most thirty digits), sums saturate (a count of transactions, the confirmations of a transaction at
block 0 under a head of 2^64-1), products are checked, block numbers past 2^48 and years outside 1970 to 9999 are refused,
a Stellar ledger's reserve past 100 XLM an entry is not believed, and a Solana `preTokenBalances` of
`-170141183460469231731687303715884105728` is skipped rather than multiplied. In the extension's WebAssembly a panic aborts
the whole worker, so no arithmetic on node data may overflow: every history parser (Esplora, TronGrid, Horizon, EVM logs and
receipts, Solana, the first-sight balance) has a test with the largest values of every width, and so do the counts,
confirmations and reserves read for Bitcoin, TRON, EVM and Stellar (`safety_tests.rs`). A sweep finds the next one
without being told where to look (`tests/hostile_numbers.rs`): the answers recorded from the live endpoints, for every
operation the apps make, are replayed with each field made hostile (the largest number, zero, the next one over, a
negative one) in every answer of its kind at once, and a panic fails the test; the ignored variant tries every number of
every answer by itself (some fifty thousand cases, about a minute, to run before a release). What a sweep of single
numbers cannot find is a sum or a difference of two numbers that are each fine (a head of 2^64-1 less a block at 0), and
the places found that way have tests of their own. Turning on `clippy::arithmetic_side_effects` for the parsers would find
those too, and is not done: it names 228 sites in this crate's library code (counted on 2026-11-02), every one of which
would need reading and most an `allow` with its reason.

## Prices

From **Chainlink's feeds on chain**, read by `latestRoundData()` through Multicall3 in one `eth_call` per chain, with no
price API. Every coin the wallet lists has a feed (BNB Chain carries nine of them; TAO's is on Ethereum), so **no on-chain
pool is used for any**. A feed's `description()` and `decimals()` are checked the first time (a feed that was replaced is
refused, not misread), an answer older than its heartbeat and five minutes is marked `stale`, and the 24-hour change is found
from the feed's own rounds (a ladder of rounds going back, then up to five narrower questions that end on the two rounds
either side of a day ago: two to six `eth_call`s a chain, one after the other, once an hour; five on BNB Chain and two on
Ethereum when measured on 2026-11-01; the price is what the last round before that moment said, however long before it that
was written). **The prices do not wait for that search for longer than four seconds**, the two chains searched at once: a
node that takes seconds over every question (PublicNode's BNB Chain endpoint took 4 to 18 s over state reads) would
otherwise hold them back for the best part of a minute. A coin whose search ran out of time is shown no change, and looked
for again after ten minutes, not an hour. A stablecoin with no reading is a dollar and marked
unread. A ticker nothing lists is left out of the answer and named in `unknown`: it never fails the prices of the others.
The client's memory (which feeds are verified, the prices a day ago) is kept between launches.

## What opening an app costs the endpoints

Measured over recordings of the live endpoints (`crates/nc-wallet-chain/tests/ops_replay.rs`, run with the result printed),
for a wallet with something on every network:

| | requests | bytes down (decoded; the endpoints gzip) |
|---|---|---|
| balances of nine networks | 13 (EVM 1 each, TRON 2, Bitcoin 2, Solana 3, Stellar 1, Bittensor 1) | ~10 KB for a small wallet |
| prices | 2 (one Multicall3 on BNB Chain, one on Ethereum for TAO) | ~6 KB |
| the prices of a day ago, at the first look and then once an hour | +7 | +95 KB (a ladder of rounds, then narrower questions, on two chains; the feeds are checked once ever, in the first reading) |
| a send, to prepare (`inputs`) | EVM 6 to 9, Solana 6, TRON 6, Bitcoin 4, Stellar 4 to 5, Bittensor 7 to 8 | EVM under 1 KB; Bittensor +700 KB the first time a runtime is met |
| a send, to price (`estimate`, after `inputs`) | EVM 6 to 8 (+2 when the speeds are asked for), Solana 5 for SOL (+1 for a token), TRON 5, Stellar 5, Bittensor 8 (counted on the recorded replay) | EVM under 1 KB |

A SOL transfer's estimate is five requests where it was three: two for the priority fee, and three for the recipient (the
usual operator's read, and the two other operators that are asked whether a program owns the account). The two are asked,
and not one, because the pool does not keep a second request away from the operator that answered the first: with two,
at least one is not that operator.

**Cadence.** The screens may ask often (the extension's panel every minute while it is open and visible, the app every
minute while it is in front); the client does not pass every ask on. It answers a balance read from the last answer for
45 seconds, and **for longer each time the answer comes back the same** (90 s, 3 min, up to 5 min); prices for two minutes;
and it reads afresh when the app says `fresh` (the person came back, pulled to refresh, an approval ended) or after a send
on that network. Nothing is read while the screen is hidden or the wallet is locked. An hour of an open panel on a wallet
that does not change: **26 requests to open, 305 in the hour** (about 5 a minute), against 900 for asking the endpoints
every time.

## Storage on the device, and what "remove wallet" clears

* **What is kept, and where.** *Android:* `SharedPreferences` in the app's private storage (no backup, no cloud: the manifest
  turns both off) for the client's memory and the last balances; the history state files, the Bitcoin account's hint and the record
  of what was just sent (all sealed) in the app's private directory.
  *Extension:* `chrome.storage.local` for the client's memory and the history states, `chrome.storage.session` (memory only,
  gone when the browser closes) for the last balances.
* **The client's memory** (the feeds checked, the prices a day ago, the Bittensor runtimes passed) holds nothing about a
  person or an address, and is stored in the clear.
* **History is sealed at rest.** It lists every address the wallet ever dealt with, and neither `chrome.storage.local` nor an
  app's private files are encrypted by the platform in a way that protects them from someone with the profile or a rooted
  phone. So each history state is sealed with AES-256-GCM under a key the engine derives from the wallet's own seed (HMAC with
  a label, never the seed itself), inside Rust. It cannot be read until the wallet is unlocked, which is when it is wanted;
  copied off the device it is noise; a different wallet cannot open it. Keys are untouched: the vault is as it was.
* **"Remove wallet" clears** the vault, the settings, the unlock throttle, the last balances, the client's memory, every
  history state (and so every note and look-alike address in it), the Bitcoin account's hint, and the client's in-memory answers
  (balances, prices, and the record of what was just sent, which is also sealed on disk). On the extension
  that is `chrome.storage.local` and `.session`; on Android the preferences and the history directory.

## Not covered, on purpose

Native-coin history on Ethereum, BNB Chain, Polygon, Base and Bittensor before the app first saw the wallet (no keyless
endpoint lists it; the answer says "History from <date>" and links the explorer); token history past what the keyless
endpoints reach on BNB Chain and Base (`docs/history.md` has the measured limits).
