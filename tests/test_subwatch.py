"""Subscription watcher — the three rules that must never regress.

Offline and deterministic: the chain is a stub, so this needs no network, no node,
no keyring and no keys.

The rules in `subwatch`'s module docstring are what is tested here, because each is
a DECISION a future edit could quietly reverse without breaking anything visible:

  1. never auto-revoke      nothing may move a paid-until backwards
  2. round down, flag       no policy is invented in code
  3. idempotent, resumable  a restart must not double-credit; an outage must not
                            lose a payment

and the fourth, which is why the ledger is keyed the way it is:

  4. time belongs to the TOKEN   paid time follows the NFT when it is sold, and the
                                 token is resolved as of the PAYMENT'S block, not
                                 whenever the watcher happens to run

Run: python server/tests/test_subwatch.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from subwatch import (DAY, MONTH, Ledger, SubWatchConfig,   # noqa: E402
                                SubWatchError, Watcher, _is_address)

NFT = "0x1111111111111111111111111111111111111111"
USDC = "0x2222222222222222222222222222222222222222"
RECV = "0x3333333333333333333333333333333333333333"
ALICE = "0x00000000000000000000000000000000000a11ce"
MALLORY = "0x00000000000000000000000000000000000ba0ba"
BOB = "0x0000000000000000000000000000000000000b0b"

USD = 10 ** 6
MONTH_UNITS = 30 * USD
T0 = 1_000_000

results: list[tuple[bool, str]] = []


def check(ok: bool, label: str) -> None:
    results.append((bool(ok), label))
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")


def raises(fn, label: str) -> None:
    try:
        fn()
    except SubWatchError:
        check(True, label)
    except Exception as e:                       # wrong exception is still a failure
        check(False, f"{label} (raised {type(e).__name__})")
    else:
        check(False, f"{label} (did not raise)")


def cfg(**over) -> SubWatchConfig:
    base = dict(receiving=RECV, pay_token=USDC, nft_contract=NFT, chain_id=1,
                decimals=6, price_month=30, confirmations=0, chunk=1000, start_block=1)
    base.update(over)
    return SubWatchConfig(**base)


class FakeChain:
    """Only the reads the watcher makes.

    `owners` may be a flat {token id: wallet} map, or {block: {token id: wallet}} to
    model ownership CHANGING over time — which is what lets a test prove the token is
    resolved as of the payment's block rather than as of the scan.
    """

    def __init__(self, head=100, owners=None, logs=None, ever_minted=None, max_supply=None,
                 block_ts=None):
        self.head = head
        self.owners = owners if owners is not None else {1: ALICE}
        self.logs = logs or []
        self.calls: list[tuple[int, int]] = []
        self.owner_scans: list[str] = []
        self.bound_calls: list[str] = []
        # Every block's timestamp is T0 unless a test overrides one, so a scan credits at
        # T0 without threading a clock through — and a test can set a block AHEAD of T0 to
        # prove crediting follows the PAYMENT's time, not the scan's.
        self._block_ts = dict(block_ts or {})
        # `ever_minted` is the highest id ever ISSUED — it does not fall when a token is
        # burned, which is exactly the difference that matters.
        self._ever = ever_minted
        self._max = max_supply

    def block_number(self): return self.head
    def assert_chain(self): return None

    def _at(self, block):
        if self.owners and all(isinstance(k, str) and k.startswith("0x") for k in self.owners):
            # keyed by block tag
            known = sorted(self.owners, key=lambda b: int(b, 16))
            pick = None
            for b in known:
                if block == "latest" or int(b, 16) <= int(block, 16):
                    pick = b
            return self.owners.get(pick, {})
        return self.owners

    def highest_possible_id(self, contract, block="latest"):
        self.bound_calls.append(block)
        if self._ever is not None:
            return self._ever
        if self._max is not None:
            return self._max
        m = self._at(block)
        return max(m) if m else 0

    def total_supply(self, contract, block="latest"):
        """Present only so a test can prove the watcher does NOT reach for it."""
        raise AssertionError("the scan must never be bounded by totalSupply()")

    def owners_of(self, contract, token_ids, block="latest"):
        self.owner_scans.append(block)
        m = self._at(block)
        return {t: m[t] for t in token_ids if t in m}

    def balance_of(self, contract, wallet, block="latest"):
        return sum(1 for o in self._at(block).values() if o.lower() == wallet.lower())

    def block_timestamp(self, block):
        b = int(block, 16) if isinstance(block, str) and block != "latest" else block
        return self._block_ts.get(b, T0)

    def incoming_transfers(self, token, to, from_block, to_block):
        self.calls.append((from_block, to_block))
        return [l for l in self.logs if from_block <= l["_block"] <= to_block]


def transfer(sender, units, block=10, tx="0xdead", idx="0x0"):
    return {"transactionHash": tx, "logIndex": idx, "_block": block,
            "blockNumber": hex(block),
            "topics": ["0xddf2",
                       "0x" + sender.replace("0x", "").rjust(64, "0"),
                       "0x" + RECV.replace("0x", "").rjust(64, "0")],
            "data": hex(units)}


def ledger(tmp: Path) -> Ledger:
    return Ledger(path=tmp / "subs.json")


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="subwatch-test-"))

    # ── rule 1: never auto-revoke ────────────────────────────────────────────
    print("\nrule 1 — never auto-revoke")

    l = ledger(tmp)
    l.extend(1, 90 * DAY, now=T0)
    far = l.paid_until(1)
    l.extend(1, DAY, now=T0)
    check(l.paid_until(1) > far, "a second payment stacks onto unexpired time")

    raises(lambda: ledger(tmp).extend(1, -DAY), "negative time is refused outright")

    l = ledger(tmp)
    l.extend(1, 30 * DAY, now=T0)
    before = l.paid_until(1)
    chain = FakeChain(logs=[
        transfer(ALICE, 1, tx="0x1"),                              # underpayment
        transfer(MALLORY, MONTH_UNITS, tx="0x2"),                  # not a holder
        {"transactionHash": "0x3", "logIndex": "0x0", "_block": 10,
         "topics": ["0xddf2"], "data": "0x0"},                     # malformed
    ])
    Watcher(cfg(), chain, l).scan_once()
    check(l.paid_until(1) == before and len(l.flags) == 3,
          "underpayment, non-holder and malformed log all flag and change nothing")

    l = ledger(tmp)
    l.extend(1, 30 * DAY, now=T0)              # long expired
    later = 9_000_000
    l.extend(1, 30 * DAY, now=later)
    check(l.paid_until(1) == later + 30 * DAY,
          "a lapsed subscription restarts from now, not from the expired stamp")

    # ── rule 2: round down, flag the remainder ───────────────────────────────
    print("\nrule 2 — round down, flag the remainder")

    l = ledger(tmp)
    stats = Watcher(cfg(), FakeChain(logs=[transfer(ALICE, MONTH_UNITS + 15 * USD)]),
                    l).scan_once()
    check(stats["credited"] == 1 and l.paid_until(1) == T0 + MONTH,
          "$45 at $30/month credits ONE month, not one and a half")
    check(any(f["kind"] == "overpayment_remainder" and f["remainder"] == 15 * USD
              for f in l.flags), "and the $15 remainder is flagged for a human")

    l = ledger(tmp)
    stats = Watcher(cfg(), FakeChain(logs=[transfer(ALICE, 3 * MONTH_UNITS)]),
                    l).scan_once()
    check(stats["credited"] == 1 and stats["flagged"] == 0
          and l.paid_until(1) == T0 + 3 * MONTH,
          "an exact three-month payment credits cleanly with no flag")

    l = ledger(tmp)
    stats = Watcher(cfg(), FakeChain(logs=[transfer(ALICE, MONTH_UNITS - 1)]), l).scan_once()
    check(stats["credited"] == 0 and l.paid_until(1) == 0 and stats["flagged"] == 1,
          "one unit short of a month credits nothing and flags")

    l = ledger(tmp)
    stats = Watcher(cfg(), FakeChain(logs=[transfer(MALLORY, MONTH_UNITS)]), l).scan_once()
    kinds = [f["kind"] for f in l.flags]
    check(stats["credited"] == 0 and not l.subs
          and kinds == ["payment_from_non_holder"],
          "money from a non-holder is flagged, never credited and never refused silently")

    check(cfg().price_units == 30 * 10 ** 6 and cfg(decimals=18).price_units == 30 * 10 ** 18,
          "decimals are read, not assumed — USDC is 6, and 18 would be a trillion out")

    # ── rule 3: idempotent and resumable ─────────────────────────────────────
    print("\nrule 3 — idempotent and resumable")

    l = ledger(tmp)
    chain = FakeChain(logs=[transfer(ALICE, MONTH_UNITS)])
    w = Watcher(cfg(), chain, l)
    w.scan_once()
    first = l.paid_until(1)
    l.last_block = 0                                    # force a rescan of the same range
    w.scan_once()
    check(l.paid_until(1) == first, "rescanning the same block credits nothing twice")

    l = ledger(tmp)
    stats = Watcher(cfg(), FakeChain(logs=[
        transfer(ALICE, MONTH_UNITS, tx="0xsame", idx="0x0"),
        transfer(ALICE, MONTH_UNITS, tx="0xsame", idx="0x1"),
    ]), l).scan_once()
    check(stats["credited"] == 2 and l.paid_until(1) == T0 + 2 * MONTH,
          "two transfers in ONE transaction both count — keyed by tx AND log index")

    l = ledger(tmp)
    chain = FakeChain(head=100, logs=[transfer(ALICE, MONTH_UNITS, block=10)])
    w = Watcher(cfg(), chain, l)
    w.scan_once()
    chain.calls.clear()
    w.scan_once()
    check(l.last_block == 100 and chain.calls == [],
          "with nothing new, no range is requested at all")

    l = ledger(tmp)
    l.last_block = 50
    chain = FakeChain(head=400, logs=[transfer(ALICE, MONTH_UNITS, block=200)])
    stats = Watcher(cfg(chunk=100), chain, l).scan_once()
    # Guard the index: if the scan requested no range at all, this must report a
    # clean FAIL rather than an IndexError. A harness that crashes reads as a broken
    # harness, and the next person debugs the wrong thing.
    resumed_at = chain.calls[0][0] if chain.calls else None
    check(stats["credited"] == 1 and resumed_at == 51,
          "a payment that landed during an outage is backfilled, not skipped")

    l = ledger(tmp)
    stats = Watcher(cfg(confirmations=12),
                    FakeChain(head=100, logs=[transfer(ALICE, MONTH_UNITS, block=95)]),
                    l).scan_once()
    check(stats["credited"] == 0 and l.last_block <= 88,
          "a payment inside the reorg cushion waits rather than being credited early")

    # ── rule 4: time belongs to the token ────────────────────────────────────
    print("\nrule 4 — time belongs to the token, not the payer")

    l = ledger(tmp)
    chain = FakeChain(owners={5: ALICE}, logs=[transfer(ALICE, MONTH_UNITS)])
    Watcher(cfg(), chain, l).scan_once()
    check(l.paid_until(5) == T0 + MONTH and l.paid_until(1) == 0,
          "payment is credited to the TOKEN the payer holds, not to the payer")
    check(ALICE not in l.subs and "5" in l.subs,
          "the ledger is keyed by token id — a wallet is never a key")

    # The sale: token 5 moves to a new owner. Nothing about the record changes, and
    # that is the point — the buyer inherits the remaining time.
    check(l.is_paid(5, now=T0 + DAY),
          "after a sale the TOKEN is still paid up — time follows the NFT")

    l = ledger(tmp)
    chain = FakeChain(owners={1: ALICE, 2: ALICE}, logs=[transfer(ALICE, MONTH_UNITS)])
    stats = Watcher(cfg(), chain, l).scan_once()
    check(stats["credited"] == 0 and [f["kind"] for f in l.flags] == ["ambiguous_token"],
          "a payer holding TWO tokens is flagged, never guessed at")
    check(not l.subs, "and nothing is credited while the question is open")

    # Ownership as of the PAYMENT's block, not the scan's. Token 5 was Alice's when she
    # paid at block 10; by the time the watcher runs she has moved it on.
    l = ledger(tmp)
    chain = FakeChain(head=100, owners={"0x5": {5: ALICE}, "0x32": {5: MALLORY}},
                      logs=[transfer(ALICE, MONTH_UNITS, block=10)])
    stats = Watcher(cfg(), chain, l).scan_once()
    check(stats["credited"] == 1 and l.paid_until(5) == T0 + MONTH,
          "the token is resolved as of the payment's block, not as of the scan")
    check(chain.owner_scans and chain.owner_scans[0] == "0xa",
          "and ownership really was read at the payment's block, not at 'latest'")

    # ── rule 5: a burn must not hide the tokens above it ─────────────────────
    print("\nrule 5 — burned ids gap the range; the scan must not go blind")

    # Measured against the real Studio-created collection: mint 3, a HOLDER burns #2,
    # totalSupply falls to 2 while #3 is still owned. Bounding by totalSupply would stop
    # at 2 and lose #3 — a paying customer cut off because someone else burned something.
    l = ledger(tmp)
    chain = FakeChain(owners={1: MALLORY, 3: ALICE},   # 2 was burned
                      ever_minted=3,
                      logs=[transfer(ALICE, MONTH_UNITS)])
    stats = Watcher(cfg(), chain, l).scan_once()
    check(stats["credited"] == 1 and l.paid_until(3) == T0 + MONTH,
          "a token ABOVE a burned id is still found and credited")

    l = ledger(tmp)
    chain = FakeChain(owners={1: MALLORY, 3: ALICE}, ever_minted=2,   # a totalSupply-shaped bound
                      logs=[transfer(ALICE, MONTH_UNITS)])
    stats = Watcher(cfg(), chain, l).scan_once()
    check(stats["credited"] == 0 and [f["kind"] for f in l.flags] == ["payment_from_non_holder"],
          "and with a too-low bound it flags rather than silently crediting the wrong token")

    l = ledger(tmp)
    chain = FakeChain(owners={2: ALICE}, max_supply=333,
                      logs=[transfer(ALICE, MONTH_UNITS)])
    stats = Watcher(cfg(), chain, l).scan_once()
    check(stats["credited"] == 1 and l.paid_until(2) == T0 + MONTH,
          "maxSupply is an acceptable fallback bound — burning never frees supply")

    # The tripwire: FakeChain.total_supply raises. If the watcher ever reaches for it
    # again, every scan in this file dies loudly rather than quietly going blind.
    check(chain.bound_calls and "total_supply" not in str(chain.bound_calls),
          "the bound is asked for explicitly, and totalSupply is never consulted")

    # ── rule 6: credit at the payment's time, not the scan's ─────────────────
    print("\nrule 6 — credit follows the payment's block time, not when we scanned")

    # A live time-warped fork exposed this: subwatch credited from wall-clock scan time,
    # so a payment whose block was 31 days ahead was credited 31 days short. In production
    # the gap is the watcher's LAG — a lapsed renewer processed an hour late loses an hour.
    AHEAD = T0 + 31 * DAY
    l = ledger(tmp)
    chain = FakeChain(owners={1: ALICE}, block_ts={10: AHEAD},
                      logs=[transfer(ALICE, MONTH_UNITS, block=10)])
    Watcher(cfg(), chain, l).scan_once()
    check(l.paid_until(1) == AHEAD + MONTH,
          "credited from the PAYMENT's block time, not from T0 when the scan ran")

    # A backlog: two payments, later block later in time. Each credits from its own block.
    l = ledger(tmp)
    chain = FakeChain(owners={1: ALICE},
                      block_ts={10: T0, 20: T0 + 10 * DAY},
                      logs=[transfer(ALICE, MONTH_UNITS, block=10, tx="0x1"),
                            transfer(ALICE, MONTH_UNITS, block=20, tx="0x2")])
    Watcher(cfg(), chain, l).scan_once()
    # First stacks from T0; second renews an already-active sub, so it stacks onto the
    # existing expiry (T0 + 30d), which is still ahead of block 20's time (T0 + 10d).
    check(l.paid_until(1) == T0 + 2 * MONTH,
          "a stacked renewal adds to the existing expiry regardless of scan lag")

    # ── rule 7: orphaned paid time (burn re-check) ───────────────────────────
    print("\nrule 7 — active paid time on a burned token is surfaced, not auto-anything")

    # token 5 was paid (active), then burned: absent from owners, and 5 <= ever-minted(10).
    l = ledger(tmp)
    l.extend(5, 30 * DAY, payer=ALICE, now=T0)
    chain = FakeChain(owners={1: MALLORY}, ever_minted=10)   # 5 gone, 1 still around
    orphans = Watcher(cfg(), chain, l).check_orphans(now=T0 + DAY)
    check([o["token"] for o in orphans] == [5],
          "a burned token with active paid time is reported as an orphan")
    check(l.paid_until(5) == T0 + 30 * DAY,
          "and its record is NOT touched — the alarm informs, it never edits")
    check([f["kind"] for f in l.flags] == ["orphaned_paid_time"],
          "exactly one flag is raised")

    # never-minted id: a typo'd grant for 999 (> ever-minted) must NOT alarm.
    l = ledger(tmp)
    l.extend(999, 30 * DAY, now=T0)              # mistaken grant
    chain = FakeChain(owners={1: ALICE}, ever_minted=36)
    orphans = Watcher(cfg(), chain, l).check_orphans(now=T0 + DAY)
    check(orphans == [] and not l.flags,
          "a never-issued id (above ever-minted) is not mistaken for a burn")

    # a LAPSED burned token has no unused time to refund — no alarm.
    l = ledger(tmp)
    l.extend(5, 30 * DAY, now=T0)
    chain = FakeChain(owners={1: ALICE}, ever_minted=10)
    orphans = Watcher(cfg(), chain, l).check_orphans(now=T0 + 60 * DAY)   # long lapsed
    check(orphans == [], "a burned token whose time already lapsed is not an orphan")

    # a still-owned token is never an orphan, however it changed hands.
    l = ledger(tmp)
    l.extend(5, 30 * DAY, now=T0)
    chain = FakeChain(owners={5: BOB}, ever_minted=10)     # 5 exists, sold to BOB
    orphans = Watcher(cfg(), chain, l).check_orphans(now=T0 + DAY)
    check(orphans == [], "a token that still exists is fine even after a transfer")

    # dedup: re-checking the same orphan does not pile up flags.
    l = ledger(tmp)
    l.extend(5, 30 * DAY, now=T0)
    chain = FakeChain(owners={1: ALICE}, ever_minted=10)
    w = Watcher(cfg(), chain, l)
    w.check_orphans(now=T0 + DAY)
    w.check_orphans(now=T0 + 2 * DAY)
    check(sum(1 for f in l.flags if f["kind"] == "orphaned_paid_time") == 1,
          "an orphan seen on two scans alarms once, not twice")

    # ── last_payment_at ──────────────────────────────────────────────────────
    print("\nlast_payment_at — stamped at credit, nullable for legacy records")
    l = ledger(tmp)
    l.extend(5, 30 * DAY, now=T0)
    check(l.subs["5"].get("last_payment_at") == T0,
          "last_payment_at is the credit's block time")
    # A legacy record without the field must read as None, never crash.
    l.subs["9"] = {"paid_until": T0 + 30 * DAY}          # no last_payment_at key
    check(l.subs["9"].get("last_payment_at") is None,
          "a record predating the field renders as None, not a guess")

    # ── rule 8: the pending list (confirmation-window backlog) ───────────────
    print("\nrule 8 — observed-but-uncredited payments show as pending, then hand off")

    # A payment inside the confirmation window: seen, not yet credited, shows pending.
    l = ledger(tmp)
    chain = FakeChain(head=100, owners={5: ALICE},
                      logs=[transfer(ALICE, MONTH_UNITS, block=95, tx="0xaa")])   # block 95, head 100
    n = Watcher(cfg(confirmations=12), chain, l).scan_pending(wall_now=T0)
    check(n == 1 and l.pending and l.pending[0]["from"] == ALICE.lower(),
          "a payment inside the confirmation window is recorded pending")
    check(l.confirming_for(ALICE) and not l.confirming_for(MALLORY),
          "confirming_for is true for the payer, false for anyone else")

    # Dedup: scanning again neither duplicates it NOR re-stamps seen_at — if it re-stamped,
    # the entry would refresh forever and never age out to needs_review.
    Watcher(cfg(confirmations=12), chain, l).scan_pending(wall_now=T0 + 5)
    check(len(l.pending) == 1 and l.pending[0]["seen_at"] == T0,
          "re-scanning keeps one entry AND preserves its original seen_at")

    # Hand-off: once credited (tx in seen), it leaves pending.
    l2 = ledger(tmp)
    l2.pending = [{"tx": "0xbb", "from": ALICE.lower(), "amount": MONTH_UNITS,
                   "block": 50, "seen_at": T0}]
    l2.seen.add("0xbb:0x0")
    chain2 = FakeChain(head=100, owners={5: ALICE}, logs=[])
    Watcher(cfg(confirmations=12), chain2, l2).scan_pending(wall_now=T0 + 10)
    check(l2.pending == [], "a credited payment leaves the pending list (hands off to active)")

    # Aged-out: a stuck entry becomes needs_review, not eternal confirming.
    l3 = ledger(tmp)
    l3.pending = [{"tx": "0xcc", "from": ALICE.lower(), "amount": MONTH_UNITS,
                   "block": 999, "seen_at": T0}]
    chain3 = FakeChain(head=100, owners={5: ALICE}, logs=[])
    Watcher(cfg(confirmations=12, pending_ttl_s=100), chain3, l3).scan_pending(wall_now=T0 + 200)
    check(l3.pending == [] and [f["kind"] for f in l3.flags] == ["stuck_pending"],
          "a pending entry older than the ttl escalates to needs_review and drops")

    # pending survives a ledger round-trip.
    l4 = ledger(tmp)
    l4.pending = [{"tx": "0xdd", "from": ALICE.lower(), "amount": 1, "block": 1, "seen_at": T0}]
    l4.save()
    check(Ledger.load(l4.path).pending == l4.pending, "pending round-trips through disk")

    # ── the ledger itself ────────────────────────────────────────────────────
    print("\nthe ledger")

    l = ledger(tmp)
    l.extend(1, 30 * DAY, paid_units=MONTH_UNITS, now=T0)
    l.seen.add("0xa:0x0")
    l.flag("thing", "detail")
    l.last_block = 42
    l.save()
    back = Ledger.load(l.path)
    check(back.paid_until(1) == l.paid_until(1) and back.seen == l.seen
          and back.last_block == 42 and len(back.flags) == 1,
          "the ledger round-trips through disk without losing anything")

    bad = tmp / "future.json"
    bad.write_text(json.dumps({"version": 99, "subs": {}}), encoding="utf-8")
    raises(lambda: Ledger.load(bad), "a ledger from a future version is refused, not guessed at")

    l = ledger(tmp)
    l.subs["1"] = {"paid_until": "not-a-number"}
    check(l.is_paid(1) is False,
          "a corrupt record answers the gate False rather than raising")

    l = ledger(tmp)
    l.extend("7", 30 * DAY, now=T0)
    check(l.is_paid(7, now=T0 + 1) and l.is_paid("7", now=T0 + 1),
          "a token id reads the same whether given as int or str")

    # ── config ───────────────────────────────────────────────────────────────
    print("\nconfig")

    for bad_addr in ("", "0x123", "not-an-address", "1234567890" * 4):
        raises(lambda b=bad_addr: cfg(receiving=b).validate(),
               f"a bad receiving address is refused: {bad_addr[:14]!r}")
        check(not _is_address(bad_addr), f"_is_address rejects {bad_addr[:14]!r}")

    cfg().validate()
    check(True, "a valid config passes validation")

    raises(lambda: SubWatchConfig.from_env({"PIKA_SUB_PRICE_MONTH": "thirty"}),
           "a non-numeric setting fails loudly at startup, not at the first payment")

    check(SubWatchConfig.from_env({"PIKA_GATE_CONTRACT": NFT}).nft_contract == NFT,
          "the collection falls back to the gate's setting — configured once")

    n_fail = sum(1 for ok, _ in results if not ok)
    print(f"\n  {len(results) - n_fail} pass · {n_fail} fail")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
