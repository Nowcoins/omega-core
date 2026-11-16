# Wallet history, read on the device

Where a wallet's activity list comes from, what the two operations are, what each
network can and cannot tell, what was measured, and what the app must do. The
code is `crates/nc-wallet-chain/src/history/`; the endpoints are
`crates/nc-wallet-chain/src/endpoints.rs`.

## The rules it keeps

* **The device only.** A history is read from public, keyless endpoints by the
  phone or the extension itself. Nothing about a wallet reaches a Nowcoin server,
  and the Nowcoin server is not asked for anything.
* **No key of any kind.** No API key, no token, no account with an operator.
* **No indexer, no explorer API, no price API.** Not Blockscout, Etherscan,
  Taostats, Covalent, Moralis, Alchemy, Infura or the like. The explorer link in
  an answer is a link the person opens; the wallet never calls it.
* **A bot challenge is not gone round.** An endpoint behind one is left alone for
  five minutes; if every endpoint that could serve a request is behind one, the
  answer says `unavailable: "history_source_blocked"`.
* **Bounded.** A call makes a handful of requests in at most 15 seconds, then
  stops where it is and says whether more remains. Nothing is lost by stopping.
* **No secret.** Bitcoin addresses are found from the account's public key
  (`zpub`) alone.

What an endpoint operator can see is what it sees for a balance: the addresses
asked about, from the device's IP address.

## The operations

Both go through the chain client's one door (`ChainClient::call(op, json)`).

### `history`

Request:

| field | |
|---|---|
| `network` | `ethereum`, `bsc`, `polygon`, `base`, `tron`, `bitcoin`, `solana`, `stellar`, `bittensor` |
| `address` | the account's address (Bitcoin: its first receive address) |
| `addresses` | Bitcoin only: other known addresses of the account |
| `zpub` | Bitcoin only: the BIP-84 account key; the account's addresses are found from it, receive and change, with a gap limit of 20 |
| `state` | the `state` of the last answer for this wallet, or absent / `null` |
| `cursor` | the `next_cursor` of the last answer, or absent for the newest |
| `limit` | items a page holds: 50 by default, 1 to 100 |
| `mode` | `newest` (default): read what is newer than the state, then give the first page. `page`: give the page at `cursor`, reading further back only if the state does not reach |
| `balance` | the native coin's balance in base units, as a decimal string. Wanted for Ethereum, BNB Chain, Polygon, Base and Bittensor (see "The coin on EVM chains and Bittensor"); ignored elsewhere |
| `fresh` | accepted and ignored: history keeps no cache of its own, every call asks the endpoints |

Answer:

```json
{
  "items": [ ... ],
  "next_cursor": "..." ,
  "state": "...",
  "coverage": { "kind": "full", "complete": true, "scanning": false, "from": null },
  "explorer_address": "https://.../address/...",
  "stale": "upstream_busy",
  "unavailable": "history_source_blocked"
}
```

* `items`: newest first (see below).
* `next_cursor`: `null` when there is nothing more to show *and* nothing more to
  read. When a call could read nothing (the endpoints were busy) and gave no
  items, it is the cursor of the request, so the same place is asked again.
* `state`: opaque. Store it, sealed, per wallet; hand it back.
* `coverage`: how much of the past the state covers.
* `explorer_address`: where the person can see the rest.
* `stale` (only when set): the endpoints could not be asked just now (the error
  code: `upstream_busy` or `upstream_unavailable`). What is shown is what was
  stored. With nothing stored, those two are returned as errors instead.
* `unavailable` (only when set): `history_source_blocked`, a bot challenge stands
  in front of every endpoint that serves this history. Say so; ask again later.

An item:

```json
{
  "hash": "0x...", "time": "2026-10-28T01:53:11Z", "kind": "transfer",
  "direction": "out", "asset": "USDT", "contract": "0xdAC1...",
  "amount": "7231635496", "decimals": 6, "counterparty": "0x28C6...",
  "fee": { "asset": "ETH", "amount": "10354892702221", "decimals": 18 },
  "status": "confirmed", "confirmations": 1468, "block": 26288020,
  "memo": "...", "observed": true, "poisoned": true, "look_alike_of": "0x..."
}
```

* `kind`: `transfer`, or `call` (a transaction that moved no listed asset: a
  contract call, an approval, a failed send; it cost its fee, `amount` is `"0"`).
* `direction`: `in`, `out`, or `self` (between the account's own addresses).
* `amount` and `fee.amount`: base units as decimal strings (so a 256-bit value
  survives). `fee` is the network fee **the account paid** (null when someone else
  paid, or when it is not known yet).
* `status`: `pending`, `confirmed`, `failed`. `confirmations` is null when the
  network gives no block height to count from. **`confirmed` and `failed` mean that two
  independent operators agree** (next section). An item that one source calls confirmed or
  failed and no second operator has confirmed yet is `status: "pending"` with
  `unverified: true` and `reported: "confirmed"` (or `"failed"`): show it as "Unverified", not
  as received or confirmed. Asking again re-checks.
* `contract`, `memo`, `observed`, `poisoned`, `look_alike_of`: present only when
  they apply. `observed` items (see below) have an empty `hash`: link them to
  `explorer_address`, not to a transaction.
* Only the assets the wallet lists are shown: the native coin, and USDT and USDC
  where the network has them (`networks.rs`). A token the wallet does not list is
  never an item; this is also what keeps a "free token" from appearing.

### `history_note`

Request `{ network, address, state?, sent: { hash, asset, contract?, amount,
decimals, to, fee?: { asset, amount, decimals }, time?, nonce? } }`, answer `{ state }`.
`nonce` is the account's nonce the send used (Bittensor only; a number or a decimal string
within 32 bits, else `invalid_request`). When the app leaves it out, the client uses the nonce the
app told it with the broadcast of the same hash, which it keeps for ten minutes.

The app calls it once, right after a broadcast succeeds. The send is kept in the
state as a *pending* item shown at the top, and is replaced by the chain's own
item once the chain history has the same hash. `asset` must be the network's
coin or a listed token (else `invalid_request`). On a coin send the balance
the state remembers is lowered by the amount and the fee at once, so the fall is
not mistaken for something else. How a note ends: on Bitcoin, TRON, Stellar and
Solana the chain's own item replaces it; on EVM chains a coin send settles when its
receipt exists (confirmed, or failed), a token send is replaced by the logs'
transfer (or becomes a failed call if its receipt says it failed), and a note
nothing has heard of for three days is forgotten; on Bittensor, whose nodes keep no
index of extrinsics by hash, by the account's nonce on chain (next section).

### Errors

`invalid_request`, `invalid_address`, `unknown_network`: the request is wrong
(this includes a `cursor` that is not one this wallet gave, `mode` other than
the two, `zpub` or `addresses` on a network other than Bitcoin). `upstream_busy`,
`upstream_unavailable`: retryable; see `stale`. A `state` that is not one, is
from a newer version, or is for another wallet is not an error: it is not used and
the history starts again.

## A second operator's agreement

A history is read from one source, and one operator (or whatever sits between the device and it) could
invent a payment or call an unmined one confirmed. `src/history/verify.rs` therefore asks **two independent
operators** (`Need::independent`: two organisations, not two hosts of one) for the transaction by its hash, and
the item is `confirmed` only when both have it in the same block with the same effect on this account. The
check is made once per item and kept (`vf` in the state). It is lazy and bounded: at most 4 items a call,
newest first, 2 requests each, and only for items dated within 7 days (an older item is not
checked, and a source can date an invented item as old as it likes: that is the limit of the window).

| Network | Second opinion | Agreement |
|---|---|---|
| EVM | `eth_getTransactionReceipt` of two operators | same outcome and block; for a token, a `Transfer` log of the token for this amount to or from the address |
| Bitcoin | `/tx/{id}` of both Esplora services | the item read again from each is the same (direction, amount, block) |
| Solana | `getTransaction` of two operators | the item read again from each is the same |
| Stellar | Horizon `/transactions/{hash}` of two operators | successful, in the same ledger (amounts are the listing's word alone) |
| TRON | `gettransactioninfobyid` of two nodes | in the same block, successful (amounts are the listing's word alone) |
| Bittensor | `System.Account` of two operators | not an item's check: a send is settled by the account's nonce (below); an arrival is "Seen" |

Cost: a wallet that receives one payment a day makes two extra requests a day; a first sync of a long history
checks only its newest items and leaves older ones as they were read. `observed` arrivals have no hash and are
never "received" (they are "Seen"). With Bitcoin (two services) or any network where a second operator cannot
be asked, an item stays `unverified` until it can.

## Paging and resuming

Pages end *between* transactions, never inside one. A cursor names a position
in the history by its time, so items that arrive newer than a cursor do not move
the pages after it.

* Opening the screen or refreshing: `mode: "newest"`, `state` from before, no
  cursor. The call reads what is newer, then gives the first page.
* "Show earlier": `mode: "page"`, the same `state`, the `next_cursor` of the last
  page. If the state does not reach that far back, the call reads further back
  until the page is full, the budget is spent, or the history ends.
* **`coverage.scanning: true`** means "ask again and more will be read". The
  app does that with the returned `state` and the returned `next_cursor` (or the
  same request as before, if there was no cursor: a call that found nothing yet
  has none). It is how an older part of a long history fills in over several
  calls.
* `coverage.complete: false` with `scanning: false` means nothing more can be
  read now (no endpoint reaches further back, or one is down). Asking again
  later may help; the explorer link covers the rest.
* Keep one call in flight per wallet, and replace the stored state only with the
  `state` of an answer. Two calls from the same state would each lose the
  other's reading (nothing breaks; the later write wins).

## Coverage

```json
{ "kind": "from_first_sight", "complete": true, "scanning": false,
  "from": "2026-10-28T06:25:44Z",
  "parts": [ { "scope": "coin",   "kind": "from_first_sight", "complete": true,  "from": "..." },
             { "scope": "tokens", "kind": "partial",          "complete": false, "from": "..." } ] }
```

* `full`: everything the network has for the account, back to its first
  transaction (Bitcoin, TRON, Stellar, Solana; EVM tokens once the scan reaches
  the floor).
* `from_first_sight`: complete from the moment this wallet first looked, `from`.
  What is older is not known (see the next section).
* `partial`: read back as far as `from`; more may be found by asking again.
* On EVM networks the answer has `parts` (the coin and the tokens); `kind` is the
  least certain of them (`from_first_sight` counts as less than `partial`), `from`
  is the latest start of any part with one, and `complete` means the tokens are
  complete (the coin never can be, and does not keep a scan going).

## The sources, network by network

| Network | Read from | How much | An item is |
|---|---|---|---|
| Bitcoin | Esplora (`/address/{a}/txs`, `/txs/chain/{last}`, 25 a page) at mempool.space, with Blockstream's as the backup, over every address of the account | all | a whole transaction, netted at the account |
| TRON | TronGrid keyless: `/v1/accounts/{a}/transactions` and `/transactions/trc20`, 100 a page | all | a TRX transfer or a USDT transfer; a contract call's fee moves onto its transfer |
| Stellar | Horizon `/accounts/{a}/payments?join=transactions`, 40 operations a page, backwards for older, forwards for newer | all | an operation's effect; a swap is two items |
| Solana | `getSignaturesForAddress` (25 a page), then `getTransaction` (jsonParsed), a few at a time | all | what the transaction did to the account's SOL and listed token balances |
| Ethereum, BNB Chain, Polygon, Base: tokens | `eth_getLogs` for the listed tokens' `Transfer` with the address as sender, and as recipient | as far back as the endpoints serve logs (table below) | one transfer |
| Ethereum, BNB Chain, Polygon, Base: the coin | what the app sent (`history_note`), and a rise of the balance | from first sight | a note, or an `observed` arrival |
| Bittensor | the same | from first sight | the same |

**Bitcoin: netting.** One transaction is one item for the whole account. Nothing
of the account's spent: `in`, what was paid to the account, from the largest
input. The account spent and some output went elsewhere: `out`, the sum of what
went elsewhere (not the change, not the fee) to the largest such output. The
account spent and everything came back: `self`, which cost the fee. The fee is
shown when the account funded the whole transaction (a shared one shows none).
Pending transactions keep the time they were first seen and are removed when the
mempool no longer has them. The addresses of a `zpub` are walked with the gap
limit of 20 on each chain; the lookups run four at a time at two requests a
second per Esplora, so an account with many used addresses takes several calls
the first time (the walk and the reading resume from the state).

**TRON.** Two lists, read by time with `min_timestamp` / `max_timestamp`. Items
older than the oldest page of a list that is not fully read are held back, so
what is shown is always a whole recent stretch. Only TronGrid has the `/v1`
account API; the plain TRON nodes in the pool refuse that need.

**Stellar.** An operation moved something only if the transaction succeeded; a
failed one is a `call` that cost its fee if the account sent it. An asset the
wallet does not list is not shown. The fee of a transaction of several
operations is shown once.

**Solana.** The effect is read from the pre- and post-balances, not from the
instructions, so whatever program moved the coin (a swap, a staking payout) is
seen as what it did. Signatures not yet read wait in the state (`pending`); the
newest are read first.

## Tokens on EVM chains: the scan

One `eth_getLogs` per direction asks for the listed tokens' `Transfer` logs with
the address in the sender topic or the recipient topic. A scan goes back in
windows of blocks. Endpoints differ a great deal, so each window is chosen from
what the endpoints that can serve its depth allow (their list in
`endpoints.rs`), then corrected by what they answer:

* a refusal that says the range is too wide (with a number or without) narrows
  the window and is remembered for that endpoint;
* "archive requests need a token" and the like mean that endpoint does not
  reach that far back; that too is remembered, and another is asked;
* "too many results" halves the window;
* a wide window nobody answered in time is narrowed (a slow answer is more
  likely too much work than every endpoint being down);
* an endpoint that answers under 1,000 blocks a query is not used, and a scan
  that would need more than 400 windows of under 5,000 blocks is not walked;
* the two directions are asked side by side.

The scan stops at the *floor*: block 4,600,000 on Ethereum (before USDT existed),
0 elsewhere. The logs carry `blockTimestamp` where the node adds it; otherwise a
block's date is counted back from the head.

**Measured, from this machine, 2026-10-28.** Span is blocks a query; reach is how
far back from the head.

| Chain | Endpoint | Logs | Notes |
|---|---|---|---|
| Ethereum | tenderly public gateway | any span, whole chain, up to 20,000 results (22 M blocks in 6 s) | what makes full history of USDT and USDC a few requests |
| | mevblocker | 100,000 blocks, archive | logs only (a private relay) |
| | publicnode (2 hosts) | 10,000 blocks, back 10,000 (33 h) | |
| | drpc | 100 blocks | |
| | meowrpc | refused | |
| BNB Chain | publicnode | 50,000 blocks, back about 325,000 (41 h) | |
| | 48 Club, bloXroute | 5,000 blocks, back at least 190,000 (24 h) | logs only |
| | blockrazor | 25 blocks | too narrow to use |
| | bnbchain.org (3 hosts) | refused ("limit exceeded" for one block) | |
| Polygon | tenderly | no limit found | whole history of the listed tokens in about 9 requests |
| | publicnode | 10,000 blocks, back about 2.2 M (4 weeks) | |
| | drpc | 100 blocks | |
| Base | publicnode | allows 50,000 blocks, but the USDC volume makes that take 6 to 10 s: held to 20,000; back about 2.1 M (7 weeks) | |
| | tenderly | 1,000 blocks, archive | |
| | drpc | 100 blocks | |
| | Base's own, meowrpc | refused logs | |

What follows from it: **Ethereum and Polygon** get their full token history in
one call or two. **BNB Chain** goes back about 41 hours (what PublicNode reaches), over
some three calls; older transfers are not reachable without a key, and the
coverage says `partial` with the date reached. **Base** goes back about a day and
a half a call, up to seven weeks over some thirty calls; after that nothing
reaches further. Both stay `partial` and, once no endpoint reaches the next
block, `scanning` becomes false. These are limits of keyless public endpoints,
not of the wallet; a key would lift them and a key is not allowed.

## The coin on EVM chains and Bittensor

No keyless endpoint lists an address's native transfers (that is what an indexer
is for, and none is used). So the coin's history is **from first sight**:

* what the app sent, via `history_note`, shown pending until a receipt settles it
  (EVM: the receipt's units used times the price paid, plus the layer-1 data fee
  on Base, is its network fee) or, on Bittensor, the account's nonce on chain;
* what arrived, seen as a rise of the balance the app passes in `balance`: the
  state keeps the balance as it will be once pending sends are mined; a balance
  above that plus the unmined sends is an *arrival*, an `observed` item with no
  hash and no counterparty, dated when it was seen. A fall that the sends do not
  explain is never made into an arrival.

`balance` therefore must be passed on **every** call for these networks, from the
app's own latest read. The first call takes the balance as the past, not an
arrival.

## A Bittensor send is settled by the account's nonce

The nodes keep no index of extrinsics by hash, and a node can accept an extrinsic and drop it from its pool. So a timer
cannot say that a send came in. The note keeps the account's nonce the send used; each call that finds a note waiting asks
two operators for `System.Account` (the extrinsics the account has had included, two requests) and settles by it:

* the account's nonce is **past** the send's: it came in, a confirmed item;
* it is not, and the send's era is over (fifteen minutes after the note: the extrinsic lives for 64 blocks of twelve seconds
  from the block it was built on): it never came in. The item is **failed**, a `call` of amount `0` with no fee (it moved
  nothing and cost nothing, as a failed send is told elsewhere), and the balance the note had lowered is whole again, so
  the money is not then "seen" arriving;
* otherwise it waits, as long as it takes. One operator's answer, or two that differ with no third to settle them,
  settles nothing. A note with no nonce (an older app's, or one made without a broadcast) waits for nothing and is
  forgotten after three days.

**Confirmed means included, not that the transfer succeeded.** The account's nonce passes a send's when its extrinsic is in
a block, whether or not its call then worked out. A transfer that fails once it is included (the nonce still advances and the
fee is still charged, but nothing moves) is shown as a confirmed send of its amount, and the amount that never left is
noticed later as a rise of the balance and shown as a "Seen" arrival, as it was under the timer this replaced; the nodes keep
no receipt to ask for the call's outcome, so the balance is what shows whether the money moved. The two operators are
read at their best block, not a finalized one, so a verdict is as final as the chain's tip is.

## An arrival that was only noticed

For the coin of the EVM networks and Bittensor, a balance higher than the sends explain is an arrival ("Seen", with no
transaction). It is recorded only when a second reading, at least 20 seconds after the first, still shows the rise (the lower of
the two counts), and never within ten minutes after this wallet's own send: a node that lags, or a number the app kept from before
the send, would otherwise show the money that left as money that came, for good. A rise seen once and gone is dropped.
It is dated when first noticed.

## Address poisoning

Computed on the device, from the state alone. An incoming transfer is flagged
`poisoned: true`, with `look_alike_of` the address it imitates, when: it has a
counterparty; its amount is under the dust level for its asset; the sender is
not an address this wallet has sent to; and the sender begins and ends with the
same four characters (after any `0x`) as an address it *has* sent to. The
addresses sent to are remembered past the items kept (the last 200). Dust levels:
USDT, USDC, TRX, XLM under 0.01; ETH, BNB, POL under 0.000001; BTC under 2,000
sat; SOL under 0.00001; TAO under 0.0001. An observed arrival is never flagged
(it has no sender).

## The state

One JSON text (short keys, `v: 1`), plain: the engine seals it at rest. A state
whose version this code does not know is not used. It holds up to 2,000 items
(the oldest are dropped past that; the explorer link covers them), up to 40 notes
and 200 look-alike addresses, the balance, the first-sight time, and each source's
own place (cursors, scan ends, the Bitcoin addresses found). It is the owner of
the history: the app keeps nothing else. Typical size 1 to 30 KB; 180 KB with
2,000 items.

## What a call costs

Measured on the live endpoints.

| | requests | bytes down | time |
|---|---|---|---|
| Ethereum, a light wallet (5 items) | 5 | 7 KB | 2 s |
| Ethereum, a busy one (2,000 items in 4 calls) | 1 to 4 | 0.3 MB | up to 10 s |
| Polygon, the first call of a busy wallet | 9 | 0.8 MB | 7 s |
| BNB Chain, a call of the partial scan | 5 to 7 | under 1 KB | up to 16 s |
| Base, a call of the partial scan | 7 to 11 | under 1 KB | 11 to 17 s |
| TRON, newest page of two lists (100 records each) | 2 | 156 KB | 1 s |
| Stellar, a page of 40 operations with their transactions | 1 | 30 KB to 485 KB (2 to 12 KB an operation) | 0.1 to 3 s |
| Bitcoin, one address of 8 transactions | 2 | 29 KB | 0.3 s |
| Bitcoin, an account walked from its zpub | 16 to 60 | 20 to 55 KB (a busy address more) | up to 16 s a call, one to three calls |
| Solana, one transaction | 3 | 8 KB | 0.3 s |

Request budgets per call: Bitcoin 16, Solana 14, EVM and TRON 10, Stellar 8,
Bittensor 6 (a lookup of four addresses side by side counts as one), and 15
seconds on the wall for all.

## Not covered, on purpose or for want of a source

* The native coin on EVM and Bittensor before first sight; internal transfers
  (a contract paying the account) on EVM; staking and delegation on Bittensor.
* A token the wallet does not list; NFTs.
* EVM tokens past what the public endpoints serve (BNB Chain, Base).
* A Bitcoin account whose used addresses are beyond a gap of 20.
* The fee of an EVM send is read from its receipt, four a call: until its turn
  (or while no endpoint gives receipts) the item has no fee.

## Testing

`cargo test -p nc-wallet-chain` runs its unit and end-to-end tests over scripted
endpoints, and some over answers recorded from the live endpoints on 2026-10-28
(`tests/fixtures/history/`): no network. The live check is by hand, read-only,
keyless:

```
cargo run -p nc-wallet-chain --example history_smoke -- --only base --rounds 4
cargo run -p nc-wallet-chain --example history_smoke -- --only tron \
    --address TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9 --record out.json
```

`--record` writes what the endpoints said for `testing::Replay` (a rate limit
or a server error is not recorded); `HEALTH=1` prints what each endpoint has
cost.

## What the app does

1. Keep `state` per wallet (per account, for Bitcoin), sealed; hand it back;
   replace it only with an answer's.
2. Call `history` on opening the screen and on refresh (`mode: "newest"`), and
   for "Show earlier" with `mode: "page"` and the `next_cursor`. While
   `coverage.scanning` is true, call again to read more.
3. Pass `balance` on every call for Ethereum, BNB Chain, Polygon, Base and
   Bittensor. For Bitcoin pass the account's `zpub` with `address` (receive 0, the one shown): the wallet's
   Bitcoin account is the whole BIP-84 account (as its balance and its sends are), discovered with the gap
   limit of 20 on each chain (`docs/direct-chain.md`, "The Bitcoin account"), and history describes the
   same money. The state the history keeps holds what it found, so no hint goes with it.
4. Call `history_note` once after every successful broadcast.
5. Say what the coverage says: "from the day this wallet first looked" for the
   coin on the EVM chains and Bittensor; "back to <date>" for a partial scan.
6. Show `poisoned` items with a warning, `stale` as "not refreshed just now",
   and `unavailable: history_source_blocked` as "the source is not answering
   (it asks for a challenge this wallet will not answer)". The word for a fee is "network fee".
7. For `observed` items, link to `explorer_address`, not to a transaction.
