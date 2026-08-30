"""Compute the /access-state payload — SESSION + LEDGER only, no on-chain call.

The UI polls this every 8s, so it must never touch the chain: ownership re-checks live
on the gated-request path with their own TTL. Everything here comes from the session
claims (addr / tok / own, resolved once at login) and the subwatch ledger (a local file).

The SERVER decides `state`; the client never derives it, and all client time-math uses
`now` from here. Frozen at v1 — see server/models.py::AccessStateOut.
"""
from __future__ import annotations

import os
import time
from typing import Any, Mapping, Optional

from subwatch import DAY, Ledger, SubWatchConfig, _default_ledger_path


def _load_ledger(cfg: SubWatchConfig) -> Optional[Ledger]:
    """The ledger, fresh, or None if it cannot be read — which becomes `unverifiable`
    rather than a guessed state."""
    try:
        return Ledger.load(_default_ledger_path(cfg))
    except Exception:
        return None


def compute_access_state(claims: Mapping[str, Any], *, now: Optional[int] = None,
                         env: Optional[Mapping[str, str]] = None) -> dict:
    now = int(time.time()) if now is None else now
    env = os.environ if env is None else env

    wallet = claims.get("addr") or None
    tok = claims.get("tok")
    owned = [int(t) for t in claims.get("own", []) or []]
    # The access token is the session's resolved one; fall back to the lowest owned id so
    # a session minted before payment gating (tok absent) still resolves a token.
    token_id = int(tok) if tok is not None else (owned[0] if owned else None)

    base = {"v": 1, "now": now, "wallet": wallet, "token_id": token_id,
            "owned_tokens": owned, "paid_until": None, "days_remaining": None,
            "price_usdc": None, "pay_address": None, "last_payment_at": None,
            "pending_reason": None}

    cfg = SubWatchConfig.from_env(env)
    led = _load_ledger(cfg)
    if led is None:
        return {**base, "state": "unverifiable"}       # never guess

    if not owned and token_id is None:
        return {**base, "state": "no_nft"}             # login resolved zero tokens

    try:
        expiring_days = int(env.get("PIKA_ACCESS_EXPIRING_DAYS", "7"))
    except ValueError:
        expiring_days = 7
    price = cfg.price_month
    pay = cfg.receiving or None

    rec = led.subs.get(str(token_id), {}) if token_id is not None else {}
    paid_until = int(rec.get("paid_until", 0))
    last_pay = rec.get("last_payment_at")              # nullable by omission
    is_paid = paid_until > now

    # They currently HAVE access -> active / expiring. No pay_address: do not hand payment
    # instructions to someone who does not need them.
    if is_paid:
        days = max(0, (paid_until - now) // DAY)
        state = "expiring" if days <= expiring_days else "active"
        return {**base, "state": state, "paid_until": paid_until, "days_remaining": days,
                "price_usdc": price, "last_payment_at": last_pay}

    # No current access. A payment IN FLIGHT or one that needs a human comes first, so a
    # customer who just paid is not told "please pay".
    if wallet and led.confirming_for(wallet):
        return {**base, "state": "pending", "pending_reason": "confirming",
                "price_usdc": price, "pay_address": pay, "last_payment_at": last_pay}
    if wallet and led.review_pending_for(wallet):
        return {**base, "state": "pending", "pending_reason": "needs_review",
                "price_usdc": price, "pay_address": pay, "last_payment_at": last_pay}

    # Otherwise: lapsed (was paid, now expired) vs unpaid (never paid).
    state = "lapsed" if paid_until > 0 else "unpaid"
    return {**base, "state": state, "paid_until": (paid_until or None),
            "price_usdc": price, "pay_address": pay, "last_payment_at": last_pay}
