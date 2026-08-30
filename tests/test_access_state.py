"""The /access-state machine — all seven states, decided server-side from session+ledger.

No network, no FastAPI: compute_access_state is a pure function of (claims, now, env,
ledger-on-disk). Each state is pinned so the server can never emit a state the frozen v1
contract does not define, and the UI never has to derive one.

Run: python server/tests/test_access_state.py
"""
from __future__ import annotations

import sys, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from access_state import compute_access_state          # noqa: E402
from subwatch import DAY, Ledger                       # noqa: E402

ALICE = "0x00000000000000000000000000000000000a11ce"
T0 = 1_000_000
USD = 10 ** 6

results = []
def check(ok, label): results.append((bool(ok), label)); print(f"  {'PASS' if ok else 'FAIL'}  {label}")


def env(ledger_path, **over):
    e = {"PIKA_SUB_RECEIVING": "0x000000000000000000000000000000000000recv"[:42].ljust(42, "0"),
         "PIKA_SUB_PAY_TOKEN": "0x" + "2" * 40,
         "PIKA_SUB_NFT": "0x" + "1" * 40,
         "PIKA_SUB_PRICE_MONTH": "30", "PIKA_SUB_DECIMALS": "6",
         "PIKA_SUB_LEDGER": str(ledger_path)}
    e.update(over)
    return e


def claims(**over):
    c = {"addr": ALICE, "tok": 7, "own": [3, 7]}
    c.update(over)
    return c


def main():
    tmp = Path(tempfile.mkdtemp(prefix="access-state-"))

    def fresh():
        p = tmp / f"l{len(list(tmp.iterdir()))}.json"
        return Ledger(path=p), p

    print("\nthe seven states")

    # active
    l, p = fresh(); l.extend(7, 30 * DAY, now=T0); l.save()
    r = compute_access_state(claims(), now=T0 + DAY, env=env(p))
    check(r["state"] == "active" and r["days_remaining"] == 29 and r["pay_address"] is None,
          "paid, plenty of time -> active, no pay_address")

    # expiring
    l, p = fresh(); l.extend(7, 5 * DAY, now=T0); l.save()
    r = compute_access_state(claims(), now=T0 + DAY, env=env(p))
    check(r["state"] == "expiring" and r["days_remaining"] == 4,
          "paid but <= threshold days -> expiring")
    r2 = compute_access_state(claims(), now=T0 + DAY, env=env(p, PIKA_ACCESS_EXPIRING_DAYS="3"))
    check(r2["state"] == "active", "the expiring threshold is config, not code")

    # unpaid (never paid)
    l, p = fresh(); l.save()
    r = compute_access_state(claims(), now=T0, env=env(p))
    check(r["state"] == "unpaid" and r["pay_address"] and r["price_usdc"] == 30
          and r["paid_until"] is None,
          "never paid -> unpaid, WITH pay instructions")

    # lapsed (paid, expired)
    l, p = fresh(); l.extend(7, 30 * DAY, now=T0); l.save()
    r = compute_access_state(claims(), now=T0 + 60 * DAY, env=env(p))
    check(r["state"] == "lapsed" and r["paid_until"] and r["pay_address"],
          "was paid, now expired -> lapsed, with pay instructions and the old paid_until")

    # no_nft
    l, p = fresh(); l.save()
    r = compute_access_state(claims(tok=None, own=[]), now=T0, env=env(p))
    check(r["state"] == "no_nft" and r["pay_address"] is None,
          "no owned tokens -> no_nft, no payment instructions")

    # pending — confirming
    l, p = fresh()
    l.pending = [{"tx": "0xaa", "from": ALICE, "amount": 30 * USD, "block": 1, "seen_at": T0}]
    l.save()
    r = compute_access_state(claims(), now=T0, env=env(p))
    check(r["state"] == "pending" and r["pending_reason"] == "confirming" and r["pay_address"],
          "an in-flight payment from the session wallet -> pending/confirming")

    # confirming is only for THIS wallet
    r2 = compute_access_state(claims(addr="0x" + "b" * 40), now=T0, env=env(p))
    check(r2["state"] != "pending" or r2["pending_reason"] != "confirming",
          "someone else's in-flight payment does not show as this wallet's confirming")

    # pending — needs_review (ambiguous flag open for this wallet)
    l, p = fresh()
    l.flag("ambiguous_token", "held several", sender=ALICE, token=None)
    l.save()
    r = compute_access_state(claims(), now=T0, env=env(p))
    check(r["state"] == "pending" and r["pending_reason"] == "needs_review",
          "an open ambiguity flag for the wallet -> pending/needs_review")

    # active BEATS a stale pending: if they currently have access, that wins
    l, p = fresh()
    l.extend(7, 30 * DAY, now=T0)
    l.pending = [{"tx": "0xbb", "from": ALICE, "amount": 30 * USD, "block": 1, "seen_at": T0}]
    l.save()
    r = compute_access_state(claims(), now=T0 + DAY, env=env(p))
    check(r["state"] == "active", "a renewal in flight while already active still reads active")

    # a MISSING ledger is a valid EMPTY one (holder, no payments yet) -> unpaid, NOT
    # unverifiable. unverifiable is reserved for a ledger that cannot be read at all.
    r = compute_access_state(claims(), now=T0, env=env(tmp / "does-not-exist.json"))
    check(r["state"] == "unpaid",
          "a missing ledger is an empty one -> unpaid, not a false unverifiable")

    # unverifiable — a genuinely UNREADABLE ledger (wrong schema version -> load raises)
    corrupt = tmp / "corrupt.json"
    corrupt.write_text('{"version": 99, "subs": {}}', encoding="utf-8")
    r = compute_access_state(claims(), now=T0, env=env(corrupt))
    check(r["state"] == "unverifiable",
          "an unreadable ledger -> unverifiable, never a guessed state")

    # ── invariants across every state ────────────────────────────────────────
    print("\ninvariants")
    l, p = fresh(); l.extend(7, 30 * DAY, now=T0); l.save()
    ok_states = {"active", "expiring", "unpaid", "lapsed", "no_nft", "pending", "unverifiable"}
    for now, cl in [(T0 + DAY, claims()), (T0, claims(tok=None, own=[])),
                    (T0 + 99 * DAY, claims())]:
        r = compute_access_state(cl, now=now, env=env(p))
        check(r["state"] in ok_states and r["v"] == 1 and r["now"] == now,
              f"state {r['state']!r} is in the contract, v=1, now echoed")

    # now is always the server clock
    r = compute_access_state(claims(), now=424242, env=env(p))
    check(r["now"] == 424242, "now is the server clock the client must use")

    n_fail = sum(1 for ok, _ in results if not ok)
    print(f"\n  {len(results) - n_fail} pass · {n_fail} fail")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
