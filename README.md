# p0aio-subwatch

**An on-chain USDC access-pass watcher.** It watches for stablecoin payments to one
wallet you control, works out how much access time each one bought, and records a
`paid-through` date **per NFT token id**. Anything it can't decide confidently, it
**flags for a human** instead of guessing.

This is the payment/tracking layer behind [p0aio](https://p0a.io) — open-sourced so
anyone can read exactly how a payment becomes access time. There is no magic and no
custody: the money moves wallet-to-wallet on a public blockchain, and this code only
*observes* it.

## The one thing to know

> **This code never touches your money.** It holds no private key and signs nothing —
> it calls `eth_getLogs` and `eth_call` and nothing else. A compromised host can corrupt
> the local ledger (annoying, and fully recoverable by re-reading the chain) but **cannot
> move a cent.** The receiving wallet's key lives wherever you keep it — never here.

## How it works

1. Members send USDC (or any ERC-20 stablecoin) to a **receiving wallet** you control.
2. subwatch reads those transfers from the chain, waits out a reorg cushion, and for
   each payment resolves **which NFT the payer held _at the block the payment landed in_**.
3. It credits that **token id** with whole months of access time, moving its
   `paid-through` date forward. Access time belongs to the *asset*: sell the NFT and the
   remaining time goes with it.
4. Your gate asks one question — `is_paid(token_id)` — and enforces access.

Because it's keyed by token id and credits at the payment's own block, it behaves
identically to a `tokenId -> paidUntil` smart contract. Adopting a real contract later is
an import, not a rewrite.

### The honest trade-off

A smart contract's `paid-until` would be **trustless on-chain**. Here, the **payment** is
still fully public and verifiable on-chain — anyone can look up every transfer to the
receiving wallet — while the **crediting** is done by *this* open-source, non-custodial
code. So: your payment is trustless; the bookkeeping is open to inspection.

## The three rules

1. **Never auto-revoke.** No code path reduces a `paid-until`. Ambiguity keeps the
   member's access and lands in a review queue — never "cut off at 3am mid-drop".
2. **Round down, flag the remainder.** $45 at $30/month credits **one** month and flags
   the $15. Policy is not invented in code.
3. **Idempotent and resumable.** Every credited transfer is recorded by `(tx hash, log
   index)`; a restart never double-credits and an outage never silently drops a payment.

## Configuration

Everything is environment-driven. The RPC URL is the only secret — **keep it out of
source control.**

| Variable | Meaning | Example |
|---|---|---|
| `PIKA_SUB_RPC_URL` | Ethereum JSON-RPC endpoint (a secret — embeds an API key) | `https://…/v2/<key>` |
| `PIKA_SUB_CHAIN_ID` | chain id | `1` |
| `PIKA_SUB_RECEIVING` | the wallet payments are sent to | `0x…` |
| `PIKA_SUB_NFT` | the access-NFT collection | `0x…` |
| `PIKA_SUB_PAY_TOKEN` | the stablecoin | USDC `0xA0b8…eB48` |
| `PIKA_SUB_PRICE_MONTH` | price per 30 days, in whole token units | `30` |
| `PIKA_SUB_DECIMALS` | token decimals (USDC is **6**, not 18) | `6` |
| `PIKA_SUB_CONFIRMATIONS` | reorg cushion, in blocks | `12` |
| `PIKA_SUB_START_BLOCK` | first block to scan | `0` |
| `PIKA_SUB_MAX_TOKEN_ID` | scan-bound fallback when supply is unreadable | `333` |
| `PIKA_SUB_LEDGER` | path to the ledger JSON | `~/.pika/subscriptions.json` |

A "month" is **30 days exactly** — calendar months aren't something the chain knows.

## Running it

```bash
pip install -r requirements.txt
export PIKA_SUB_RPC_URL="https://…"   # never commit this
python3 subwatch.py                    # scan once and update the ledger
```

The ledger is plain JSON, keyed by token id (`paid_until`, `total_units`, `last_payer`,
…) plus a `flags` queue for anything a human should look at. Read it directly, back it
up — it holds no secrets.

## Verifying it

The suite is self-contained (a `FakeChain` with synthetic logs — no network):

```bash
python3 tests/test_subwatch.py        # the accounting: attribution, amounts, reorgs, idempotency
python3 tests/test_access_state.py    # member status: active / expiring / lapsed / confirming
python3 tests/mutate_subwatch.py      # the mutation gate — break a guard, prove a test notices
```

**The mutation gate is the point.** A green suite isn't enough for money-adjacent
accounting, so `mutate_subwatch.py` deliberately breaks each load-bearing guard (the
three rules, non-holder, ambiguous-token, underpayment, reorg cushion, the active check)
and demands a test catch it. Current result: **8 killed / 0 survived** — the suite bites.

## Live deployment

The p0aio deployment runs against these **public** addresses on Ethereum mainnet — all
verifiable on Etherscan, which is exactly the point:

- Access collection: `0x6d9ea2474bc758ae63b6c8048aece5da8ae406ff`
- Receiving wallet: `0x6e0912E13060404c3AaD09011c393331d1edE565`
- Pay token (USDC): `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`

Every access-pass payment is a public transfer to the receiving wallet — look them up
yourself.

## License

MIT — see [LICENSE](LICENSE).
