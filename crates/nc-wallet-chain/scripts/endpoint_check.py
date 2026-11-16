#!/usr/bin/env python3
"""A read-only look at every endpoint the wallet uses, as a browser would ask it. Run by hand, never by a test:

    cargo run -q -p nc-wallet-chain --example origins -- --urls | python3 crates/nc-wallet-chain/scripts/endpoint_check.py

For each endpoint: does it answer the probe a wallet makes (a block number, a balance, a tip height), how fast, and what
does it say about cross-origin requests (`Access-Control-Allow-Origin` on the answer and on a preflight). The extension
does not depend on CORS: its `host_permissions` let it read any of these. Keyless, a few requests to each, no send.
"""
import json
import sys
import time
import urllib.error
import urllib.request

ORIGIN = "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
PROBES = {
    "ethereum": ("rpc", "eth_blockNumber", []),
    "bsc": ("rpc", "eth_blockNumber", []),
    "polygon": ("rpc", "eth_blockNumber", []),
    "base": ("rpc", "eth_blockNumber", []),
    "tron": ("rpc", "eth_blockNumber", [], "/jsonrpc"),
    "solana": ("rpc", "getSlot", []),
    "bittensor": ("rpc", "chain_getFinalizedHead", []),
    "bitcoin": ("get", "/blocks/tip/height"),
    "stellar": ("get", "/ledgers?order=desc&limit=1"),
}


def call(url, data=None, headers=None, method=None):
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    started = time.time()
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, dict(response.headers), response.read(), time.time() - started
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read(), time.time() - started
    except Exception as error:  # noqa: BLE001
        return None, {}, str(error).encode(), time.time() - started


def main():
    endpoints = json.load(sys.stdin)
    print(f"{'network':<10} {'endpoint':<20} {'answer':<8} {'ms':>5}  {'ACAO (answer)':<16} {'preflight':<22} note")
    for network, specs in endpoints.items():
        probe = PROBES[network]
        for spec in specs:
            url = spec["url"]
            headers = {"Origin": ORIGIN, "Accept": "application/json", "User-Agent": "NowcoinOmega"}
            if probe[0] == "rpc":
                path = probe[3] if len(probe) > 3 else ""
                body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": probe[1], "params": probe[2]}).encode()
                post = {**headers, "Content-Type": "application/json"}
                status, got, text, took = call(url + path, body, post, "POST")
                pre_status, pre, _, _ = call(
                    url + path, None,
                    {"Origin": ORIGIN, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"},
                    "OPTIONS",
                )
                ok = status == 200 and b'"result"' in text
            else:
                status, got, text, took = call(url + probe[1], None, headers, "GET")
                pre_status, pre, _, _ = call(
                    url + probe[1], None, {"Origin": ORIGIN, "Access-Control-Request-Method": "GET"}, "OPTIONS"
                )
                ok = status is not None and 200 <= status < 300
            acao = next((v for k, v in got.items() if k.lower() == "access-control-allow-origin"), "-")
            pre_acao = next((v for k, v in pre.items() if k.lower() == "access-control-allow-origin"), "-")
            note = "" if ok else (text[:60].decode(errors="replace") if status else "no answer")
            if not ok and probe[0] == "rpc":
                # Does it answer when no Origin is sent (the Android app sends none)? Then it is
                # the app's endpoint and not the extension's (see endpoints.rs).
                bare = {k: v for k, v in post.items() if k != "Origin"}
                again, _, again_text, _ = call(url + path, body, bare, "POST")
                if again == 200 and b'"result"' in again_text:
                    note = "answers only without an Origin header: the app's, not the extension's"
            print(f"{network:<10} {spec['name']:<20} {'ok' if ok else str(status):<8} {took * 1000:>5.0f}  {acao:<16} {str(pre_status) + ' ' + pre_acao:<22} {note}")
            time.sleep(0.3)


main()
