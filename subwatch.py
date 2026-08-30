"""Subscription watcher — semi-automated manual tracking.

WHAT THIS IS. Collectors send USDC to one address we control. This notices the
payment, works out how many months it bought, and extends that wallet's paid-until
date. Everything it cannot decide confidently, it FLAGS for a human instead of
guessing.

It is the manual spreadsheet with the tedious half automated. The judgement half —
who gets access, comps, refunds, anything unusual — stays human, and a human edit
always wins over anything this file computes.

KEYED BY TOKEN ID, NOT BY WALLET, and that is the whole reason this file is shaped the
way it is. Paid time is a property of the ASSET: sell the NFT and the remaining time
goes with it, which is what makes an NFT with months on it worth more to a buyer. Key
it by wallet instead and the seller keeps the time while the buyer gets nothing — a
different product, and not the one that was promised. `src/Subscription.sol` stores
`tokenId -> paidUntil`; so does this. They agree by construction rather than by
intention, and migrating later is an import.

Which token a payer holds is resolved AT THE BLOCK THE PAYMENT LANDED IN, not at scan
time. Reading it later would mean a transfer between paying and scanning silently
credits the wrong token, and the answer would depend on when the watcher happened to
run.

WHY NOT A PAYMENT PROCESSOR. Selling automated-purchase software is a category card
processors get nervous about, and being switched off mid-month with subscribers who
have already paid is a worse failure than any amount of manual work. A wallet cannot
be deplatformed.

WHY THIS AND NOT A CONTRACT. An on-chain Subscription contract (USDC in, a paid-until
per token out) is the trustless version of exactly this. It was built and then RETIRED
for launch simplicity: a contract is immutable and deserves an audit, while this watcher
is patchable, custodies nothing, and ships today. The ledger below keeps the same shape —
token -> paid-until — so adopting a contract later is an import, not a rewrite. The
trade-off is honest: a contract's paid-until would be trustless on-chain; here the
PAYMENT is public on-chain and the CREDITING is this open-source, non-custodial code.

SECURITY POSTURE, and it matches the gate's:

  * READ ONLY. This module never signs anything and never holds a key. It calls
    eth_getLogs and eth_call and nothing else. The receiving wallet's key lives
    wherever you keep it — not here, not on the server, ideally not online. A
    compromised host can corrupt the LEDGER (annoying, recoverable from chain) but
    cannot move a cent.
  * The RPC URL is a secret — provider URLs embed an API key in the path — so it is
    read from the environment (PIKA_SUB_RPC_URL) and must be kept out of source
    control. Any Ethereum JSON-RPC endpoint works; only eth_getLogs and eth_call are
    used.
  * This is VERIFICATION logic. Reading it is the whole point of open-sourcing it —
    but it is meant to RUN where you control it (your server), against your own
    receiving wallet. It is not client software and should not be embedded in an app.

THE THREE RULES, which are design decisions and not implementation details:

  1. NEVER AUTO-REVOKE. Ambiguity keeps the customer's access and lands in the
     review queue. The failure mode must be "you look at it tomorrow", never "cut
     off at 3am mid-drop". There is no code path here that reduces a paid-until.
  2. ROUND DOWN, FLAG THE REMAINDER. $45 at $30/month credits ONE month and flags
     the $15. Policy is not invented in code.
  3. IDEMPOTENT AND RESUMABLE. Every credited transfer is recorded by
     (tx hash, log index), and scanning resumes from the last processed block. A
     restart must not double-credit, and an outage must not silently lose a payment.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

_log = logging.getLogger("pika.subwatch")

# ── chain constants ──────────────────────────────────────────────────────────
# keccak256("Transfer(address,address,uint256)")
_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
# balanceOf(address)
_BALANCE_OF_SELECTOR = "0x70a08231"
# ownerOf(uint256), maxSupply(), getMintStats(address)
_OWNER_OF_SELECTOR = "0x6352211e"
_MAX_SUPPLY_SELECTOR = "0xd5abeb01"
_MINT_STATS_SELECTOR = "0x840e15d4"
# totalSupply() is deliberately NOT used as a scan bound. See Chain.highest_possible_id.

DAY = 86_400
MONTH = 30 * DAY  # same definition the contract uses: 30 days exactly


class SubWatchError(RuntimeError):
    """Operator-facing failure. Unlike GateError this is never shown to a client."""


# ── config ───────────────────────────────────────────────────────────────────
@dataclass
class SubWatchConfig:
    """Non-secret settings. The RPC URL is deliberately absent — see module docs."""

    receiving: str = ""          # PIKA_SUB_RECEIVING — wallet collectors pay TO
    pay_token: str = ""          # PIKA_SUB_PAY_TOKEN — USDC address on this chain
    nft_contract: str = ""       # PIKA_SUB_NFT — the access collection (defaults to the gate's)
    chain_id: int = 11155111     # PIKA_SUB_CHAIN_ID — Sepolia by default, like the gate
    decimals: int = 6            # PIKA_SUB_DECIMALS — USDC is 6, NOT 18
    price_month: int = 30        # PIKA_SUB_PRICE_MONTH — whole currency units per month
    # Reorg cushion. A credited payment is never revoked (rule 1), so a payment
    # credited from a block that later reorgs out would be a gift. Cheap insurance.
    confirmations: int = 12      # PIKA_SUB_CONFIRMATIONS
    # Providers cap eth_getLogs ranges. Scan in chunks rather than discovering the
    # limit as a failure halfway through a backfill.
    chunk: int = 2_000           # PIKA_SUB_CHUNK
    start_block: int = 0         # PIKA_SUB_START_BLOCK — first scan begins here
    # The collection is not ERC721Enumerable — verified against the deployed SeaDrop
    # implementation, where tokenOfOwnerByIndex reverts — so nothing on chain maps a
    # wallet to its token. We scan ownerOf(1..N). Tractable at 333; it would not be at
    # 10,000, which makes the supply figure a constraint on this design and not just a
    # number. `totalSupply()` supplies N when the collection has it.
    max_token_id: int = 333      # PIKA_SUB_MAX_TOKEN_ID — fallback when totalSupply is absent
    # A pending payment that never confirms (reorg, a hole in scanning) must not show
    # "confirming" forever. After this it is escalated to a needs_review flag and dropped
    # from pending. Comfortably longer than confirmations * blocktime.
    pending_ttl_s: int = 3600    # PIKA_SUB_PENDING_TTL_S
    poll_s: int = 60             # PIKA_SUB_POLL_S
    ledger_path: str = ""        # PIKA_SUB_LEDGER — defaults under the state dir

    @classmethod
    def from_env(cls, e: dict[str, str] | None = None) -> "SubWatchConfig":
        e = os.environ if e is None else e

        def _int(key: str, default: int) -> int:
            raw = e.get(key, "")
            if not raw:
                return default
            try:
                return int(raw)
            except ValueError as exc:
                raise SubWatchError(f"{key} must be an integer, got {raw!r}") from exc

        return cls(
            receiving=e.get("PIKA_SUB_RECEIVING", "").strip(),
            pay_token=e.get("PIKA_SUB_PAY_TOKEN", "").strip(),
            nft_contract=(e.get("PIKA_SUB_NFT") or e.get("PIKA_GATE_CONTRACT", "")).strip(),
            chain_id=_int("PIKA_SUB_CHAIN_ID", 11155111),
            decimals=_int("PIKA_SUB_DECIMALS", 6),
            price_month=_int("PIKA_SUB_PRICE_MONTH", 30),
            confirmations=_int("PIKA_SUB_CONFIRMATIONS", 12),
            chunk=_int("PIKA_SUB_CHUNK", 2_000),
            start_block=_int("PIKA_SUB_START_BLOCK", 0),
            max_token_id=_int("PIKA_SUB_MAX_TOKEN_ID", 333),
            pending_ttl_s=_int("PIKA_SUB_PENDING_TTL_S", 3600),
            poll_s=_int("PIKA_SUB_POLL_S", 60),
            ledger_path=e.get("PIKA_SUB_LEDGER", "").strip(),
        )

    @property
    def price_units(self) -> int:
        """The monthly price in the token's own units. USDC has 6 decimals, not 18,
        and a tool that assumes otherwise is wrong by a factor of a trillion."""
        return self.price_month * (10 ** self.decimals)

    def validate(self) -> None:
        for name, value in (("PIKA_SUB_RECEIVING", self.receiving),
                            ("PIKA_SUB_PAY_TOKEN", self.pay_token),
                            ("PIKA_SUB_NFT", self.nft_contract)):
            if not _is_address(value):
                raise SubWatchError(f"{name} is not a 0x-prefixed 20-byte address: {value!r}")
        if self.price_month <= 0:
            raise SubWatchError("PIKA_SUB_PRICE_MONTH must be positive")
        if self.decimals < 2 or self.decimals > 18:
            raise SubWatchError(f"PIKA_SUB_DECIMALS looks wrong: {self.decimals}")
        if self.confirmations < 0:
            raise SubWatchError("PIKA_SUB_CONFIRMATIONS cannot be negative")
        if self.max_token_id <= 0:
            raise SubWatchError("PIKA_SUB_MAX_TOKEN_ID must be positive")


def _is_address(value: str) -> bool:
    return (isinstance(value, str) and value.startswith("0x")
            and len(value) == 42 and all(c in "0123456789abcdefABCDEF" for c in value[2:]))


# ── the ledger ───────────────────────────────────────────────────────────────
@dataclass
class Ledger:
    """token id -> paid-until, plus what we have already credited and what needs eyes.

    The same shape as `src/Subscription.sol`'s `_paidUntil` mapping, so the eventual
    on-chain move is an import. Written atomically: a half-written ledger is a customer
    with no record of having paid.
    """

    path: Path
    last_block: int = 0
    subs: dict[str, dict[str, Any]] = field(default_factory=dict)   # str(token id) -> record
    seen: set[str] = field(default_factory=set)                     # "txhash:logindex"
    flags: list[dict[str, Any]] = field(default_factory=list)
    # Observed-but-not-yet-credited payments — the confirmation-window backlog. Ephemeral
    # UX state, NOT a money record: an entry is deleted the moment it is credited, flagged,
    # or ages out. Kept so /access-state can show "confirming" without an on-chain call —
    # the WATCHER (which may do RPC) writes it, the endpoint only reads the file.
    pending: list[dict[str, Any]] = field(default_factory=list)

    # v1 keyed `subs` by WALLET. v2 keys it by TOKEN ID. Loading a v1 file as v2 would
    # read hex addresses as token ids and quietly credit nobody, so the version check
    # below refuses rather than converts — a wallet cannot be mapped to the token it
    # held months ago without chain history nobody has kept.
    VERSION = 2

    @classmethod
    def load(cls, path: str | Path) -> "Ledger":
        p = Path(path)
        if not p.exists():
            return cls(path=p)
        raw = json.loads(p.read_text(encoding="utf-8"))
        got = raw.get("version")
        if got != cls.VERSION:
            extra = ("  v1 keyed subscriptions by WALLET; v2 keys them by TOKEN ID, and "
                     "the two cannot be converted without knowing which token each payer "
                     "held at the time." if got == 1 else "")
            raise SubWatchError(
                f"ledger at {p} is version {got!r}, this code writes version "
                f"{cls.VERSION}. Refusing to touch it rather than guess.{extra}"
            )
        return cls(
            path=p,
            last_block=int(raw.get("last_block", 0)),
            subs={str(k): v for k, v in raw.get("subs", {}).items()},
            seen=set(raw.get("seen", [])),
            flags=list(raw.get("flags", [])),
            pending=list(raw.get("pending", [])),   # absent in an older file -> empty
        )

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": self.VERSION,
            "last_block": self.last_block,
            "subs": self.subs,
            "seen": sorted(self.seen),
            "flags": self.flags,
            "pending": self.pending,
        }
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.path)   # atomic on POSIX

    # -- reads -------------------------------------------------------------
    def paid_until(self, token_id: int | str) -> int:
        return int(self.subs.get(str(token_id), {}).get("paid_until", 0))

    def is_paid(self, token_id: int | str, now: int | None = None) -> bool:
        """The one question the gate asks about a token. Never raises.

        Compose it exactly as the contract does — `activeFor(wallet, tokenId)` is
        `isActive(tokenId) AND ownerOf(tokenId) == wallet`. The gate already performs
        the ownership half on chain; this is the other half, and swapping this file
        for the contract later changes nothing about how the gate asks.
        """
        try:
            return self.paid_until(token_id) > (int(time.time()) if now is None else now)
        except Exception:                      # a corrupt ledger must not throw at the gate
            return False

    def active(self, now: int | None = None) -> list[tuple[str, int]]:
        now = int(time.time()) if now is None else now
        return sorted(((t, int(v.get("paid_until", 0))) for t, v in self.subs.items()
                       if int(v.get("paid_until", 0)) > now), key=lambda t: t[1])

    # -- writes ------------------------------------------------------------
    def extend(self, token_id: int | str, seconds: int, *, paid_units: int = 0,
               note: str = "", payer: str = "", now: int | None = None) -> int:
        """Add time. RULE 1: this only ever moves paid_until FORWARD.

        Extending an unexpired subscription stacks onto the existing expiry; extending
        a lapsed one starts from now. Same arithmetic the contract uses, so the two
        cannot disagree about what a renewal is worth.
        """
        if seconds < 0:
            raise SubWatchError("extend() cannot take negative time — see rule 1")
        now = int(time.time()) if now is None else now
        key = str(token_id)
        rec = self.subs.setdefault(key, {"paid_until": 0, "total_units": 0, "note": "",
                                         "last_payer": ""})
        base = max(int(rec.get("paid_until", 0)), now)
        rec["paid_until"] = base + seconds
        rec["total_units"] = int(rec.get("total_units", 0)) + int(paid_units)
        # When the most recent credit landed, in the payment's own block time. Nullable
        # by omission: a record written before this field existed simply has no key, and
        # readers must render that as null rather than backfilling a guess.
        rec["last_payment_at"] = now
        if note:
            rec["note"] = note
        if payer:
            # Support breadcrumb only. The subscription belongs to the TOKEN; who last
            # paid for it is history, and must never be read as an ownership claim.
            rec["last_payer"] = payer.lower()
        return rec["paid_until"]

    def review_pending_for(self, wallet: str) -> bool:
        """Does this wallet have an UNRESOLVED payment that a human must sort out — an
        ambiguous payment (held several tokens) or one stuck past confirmations? Drives
        the `needs_review` pending reason."""
        w = wallet.lower()
        return any(not f.get("resolved")
                   and f.get("kind") in ("ambiguous_token", "stuck_pending")
                   and str(f.get("sender", "")).lower() == w
                   for f in self.flags)

    def confirming_for(self, wallet: str) -> bool:
        """Is there a pending (observed, uncredited) payment FROM this wallet? Drives the
        `confirming` access-state — the gap between a customer sending USDC and the credit
        landing, which is exactly where they panic."""
        w = wallet.lower()
        return any(str(p.get("from", "")).lower() == w for p in self.pending)

    def has_open_flag(self, kind: str, token_id: int | str) -> bool:
        """Is there already an UNRESOLVED flag of this kind for this token? Used so a
        recurring condition — an orphaned record re-seen every scan — alarms ONCE and
        does not bury the queue in duplicates."""
        t = str(token_id)
        return any(not f.get("resolved") and f.get("kind") == kind and str(f.get("token")) == t
                   for f in self.flags)

    def flag(self, kind: str, detail: str, **extra: Any) -> None:
        """Anything this tool will not decide on its own. Never blocks a customer."""
        self.flags.append({"ts": int(time.time()), "kind": kind, "detail": detail,
                           "resolved": False, **extra})
        _log.warning("subwatch FLAG %s: %s %s", kind, detail, extra or "")


# ── chain reads ──────────────────────────────────────────────────────────────
class Chain:
    """Read-only JSON-RPC. Never signs. Mirrors the gate's posture, including
    keeping provider errors out of anything that could be echoed onward."""

    def __init__(self, rpc_url: str, chain_id: int):
        self._url = rpc_url
        self._chain_id = chain_id

    @classmethod
    def from_env(cls, chain_id: int) -> "Chain":
        # The provider URL embeds an API key in its path, so it is a SECRET: pass it in
        # the environment, never commit it. PIKA_SUB_RPC_URL_<id> wins for a per-chain
        # URL; PIKA_SUB_RPC_URL is the single-chain fallback.
        url = os.environ.get(f"PIKA_SUB_RPC_URL_{chain_id}") or os.environ.get("PIKA_SUB_RPC_URL", "")
        if not url:
            raise SubWatchError(
                f"no RPC URL for chain {chain_id} — set PIKA_SUB_RPC_URL "
                f"(or PIKA_SUB_RPC_URL_{chain_id})")
        return cls(url, chain_id)

    def _rpc(self, method: str, params: list) -> Any:
        import httpx
        try:
            r = httpx.post(self._url, timeout=20.0,
                           json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            # httpx puts the URL — and therefore the API key — in its exception text.
            raise SubWatchError(f"RPC {method} failed: {type(e).__name__}") from None
        if "error" in data:
            raise SubWatchError(f"RPC {method} returned an error: {data['error'].get('message', '?')}")
        return data["result"]

    def assert_chain(self) -> None:
        got = int(self._rpc("eth_chainId", []), 16)
        if got != self._chain_id:
            raise SubWatchError(
                f"RPC is chain {got}, config says {self._chain_id}. Refusing to credit "
                f"payments read from the wrong chain."
            )

    def block_number(self) -> int:
        return int(self._rpc("eth_blockNumber", []), 16)

    def _rpc_batch(self, calls: list[tuple[str, list]]) -> list[Any]:
        """One HTTP round trip for many calls. Resolving which of 333 tokens a payer
        holds is 333 eth_calls; sent one at a time that is 333 round trips per payment,
        which is how a correct design becomes an unusable one."""
        import httpx
        if not calls:
            return []
        body = [{"jsonrpc": "2.0", "id": i, "method": m, "params": p}
                for i, (m, p) in enumerate(calls)]
        try:
            r = httpx.post(self._url, timeout=45.0, json=body)
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            raise SubWatchError(f"batched RPC failed: {type(e).__name__}") from None
        if not isinstance(data, list):
            raise SubWatchError("batched RPC did not return a list — provider may not support batching")
        out: list[Any] = [None] * len(calls)
        for item in data:
            idx = item.get("id")
            if not isinstance(idx, int) or not 0 <= idx < len(calls):
                raise SubWatchError("batched RPC returned an out-of-range id")
            out[idx] = None if "error" in item else item.get("result")
        return out

    def block_timestamp(self, block: str) -> int:
        """The timestamp of `block`. Credit time is WHEN THE CUSTOMER PAID, which is the
        payment's block, not when the watcher happened to scan it — otherwise a lapsed
        renewer processed an hour late silently loses that hour, and subwatch disagrees
        with the contract, which uses block.timestamp. Surfaced by a time-warped fork
        where scan-time and block-time were 31 days apart."""
        blk = self._rpc("eth_getBlockByNumber", [block if block == "latest" else block, False])
        return int(blk["timestamp"], 16)

    def balance_of(self, contract: str, wallet: str, block: str = "latest") -> int:
        data = _BALANCE_OF_SELECTOR + wallet.lower().replace("0x", "").rjust(64, "0")
        out = self._rpc("eth_call", [{"to": contract, "data": data}, block])
        return int(out, 16) if out and out != "0x" else 0

    def highest_possible_id(self, contract: str, block: str = "latest") -> int | None:
        """The largest token id that could exist. None when the collection tells us
        neither figure and the caller must fall back to config.

        DELIBERATELY NOT `totalSupply()`. The collection OpenSea Studio actually creates
        has a burn path any holder may call on their own token, and burning DECREASES
        totalSupply while leaving higher ids alive — measured on a fork against the real
        collection: mint 3, burn #2, and totalSupply reads 2 while #3 still exists. A
        scan bounded by totalSupply would stop at 2 and make #3 invisible, so a paying
        customer loses access because a DIFFERENT customer burned something.

        `getMintStats(...)[1]` is total-ever-minted: it stayed at 5 across two minters
        after a burn, while totalSupply read 4 and the highest live id was 5. It never
        decreases, so it is both correct and tight. `maxSupply()` is the looser fallback
        and is still safe, because burning does NOT free supply — minting past the cap
        after a burn is refused, also measured.
        """
        try:
            out = self._rpc("eth_call", [{
                "to": contract,
                "data": _MINT_STATS_SELECTOR + "0" * 64,   # stats for address(0); [1] is global
            }, block])
            if out and len(out) >= 2 + 64 * 2:
                total_ever = int(out[2 + 64:2 + 128], 16)
                if total_ever > 0:
                    return total_ever
        except SubWatchError:
            pass
        try:
            out = self._rpc("eth_call", [{"to": contract, "data": _MAX_SUPPLY_SELECTOR}, block])
            cap = int(out, 16) if out and out != "0x" else 0
            return cap or None
        except SubWatchError:
            return None

    def owners_of(self, contract: str, token_ids: Iterable[int], block: str = "latest") -> dict[int, str]:
        """ownerOf for many ids in one round trip. A token that does not exist reverts,
        and reverts arrive as None — absent from the result rather than guessed at."""
        ids = list(token_ids)
        calls = [("eth_call", [{"to": contract,
                                "data": _OWNER_OF_SELECTOR + hex(i)[2:].rjust(64, "0")}, block])
                 for i in ids]
        out: dict[int, str] = {}
        for tid, res in zip(ids, self._rpc_batch(calls)):
            if isinstance(res, str) and len(res) >= 42:
                out[tid] = "0x" + res[-40:]
        return out

    def incoming_transfers(self, token: str, to: str, from_block: int, to_block: int) -> list[dict]:
        """ERC-20 Transfers INTO `to`, filtered server-side by indexed topic."""
        topic_to = "0x" + to.lower().replace("0x", "").rjust(64, "0")
        return self._rpc("eth_getLogs", [{
            "address": token,
            "fromBlock": hex(from_block),
            "toBlock": hex(to_block),
            "topics": [_TRANSFER_TOPIC, None, topic_to],
        }])


# ── the watcher ──────────────────────────────────────────────────────────────
def _topic_address(topic: str) -> str:
    return "0x" + topic[-40:]


class Watcher:
    def __init__(self, cfg: SubWatchConfig, chain: Chain, ledger: Ledger):
        self.cfg, self.chain, self.ledger = cfg, chain, ledger
        self._owners_at: dict[str, dict[int, str]] = {}   # block tag -> {token id: owner}

    def _owner_map(self, block: str) -> dict[int, str]:
        """Who owned what, AS OF `block`. Cached per block: several payments can land in
        one block, and each would otherwise re-scan the whole collection."""
        if block in self._owners_at:
            return self._owners_at[block]
        top = self.chain.highest_possible_id(self.cfg.nft_contract, block) or self.cfg.max_token_id
        # Ids start at 1 and are NOT contiguous: the collection Studio creates lets any
        # holder burn their own token, which leaves a gap and lowers totalSupply. So the
        # range must be bounded by what was ever ISSUED, never by what currently exists,
        # and burned ids simply drop out of the map below (ownerOf reverts for them).
        owners = self.chain.owners_of(self.cfg.nft_contract, range(1, top + 1), block)
        self._owners_at[block] = owners
        if len(self._owners_at) > 32:                      # bounded, oldest first
            self._owners_at.pop(next(iter(self._owners_at)))
        return owners

    def _tokens_held(self, wallet: str, block: str) -> list[int]:
        w = wallet.lower()
        return sorted(t for t, o in self._owner_map(block).items() if o.lower() == w)

    def scan_once(self) -> dict[str, int]:
        """One pass. Returns a small summary so a caller can log or assert on it.

        Crediting time comes from each payment's own block (see `_credit`), never from
        when this scan runs, so a backlog processed late credits every customer from when
        they actually paid."""
        cfg, led = self.cfg, self.ledger
        head = self.chain.block_number()
        safe_head = head - cfg.confirmations
        start = led.last_block + 1 if led.last_block else cfg.start_block
        stats = {"credited": 0, "flagged": 0, "skipped": 0, "from": start, "to": safe_head}
        if safe_head < start:
            stats["to"] = led.last_block
            return stats

        block = start
        while block <= safe_head:
            upper = min(block + cfg.chunk - 1, safe_head)
            for log in self.chain.incoming_transfers(cfg.pay_token, cfg.receiving, block, upper):
                self._credit(log, stats)
            # Persist per chunk, not per scan: an interruption mid-backfill must not
            # replay work already done, and must not lose it either.
            led.last_block = upper
            led.save()
            block = upper + 1
        return stats

    def scan_pending(self, *, wall_now: int | None = None) -> int:
        """Record payments observed in the CONFIRMATION WINDOW (safe_head..head) that
        scan_once has not yet credited, so /access-state can show "confirming". Returns
        the current pending count.

        Lifecycle, per the frozen v1 contract:
          - an entry is (tx, from, amount, block, seen_at), deduped by tx hash;
          - it LEAVES the moment its tx has been credited or flagged (tx in `seen`) or
            scan_once has advanced past its block — "confirming" hands off to
            active/needs_review, it never lingers;
          - an entry older than pending_ttl_s is escalated to a needs_review flag and
            dropped, so a stuck payment becomes a human's problem, not eternal limbo.

        This is the only method that does RPC for pending; the endpoint just reads the
        file it writes, keeping /access-state session+file only.
        """
        cfg, led = self.cfg, self.ledger
        wall_now = int(time.time()) if wall_now is None else wall_now
        head = self.chain.block_number()
        safe_head = head - cfg.confirmations

        # 1. observe: transfers into the receiving wallet still inside the window. CHUNKED
        # by cfg.chunk like scan_once — the window can exceed a provider's getLogs range
        # limit (Alchemy's free tier caps it at 10 blocks), so never read it in one call.
        observed = {}
        if head > safe_head:
            lo = max(safe_head + 1, (led.last_block + 1) if led.last_block else cfg.start_block)
            b = lo
            while b <= head:
                hi = min(b + cfg.chunk - 1, head)
                for log in self.chain.incoming_transfers(cfg.pay_token, cfg.receiving, b, hi):
                    tx = log.get("transactionHash")
                    topics = log.get("topics") or []
                    if not tx or len(topics) < 3:
                        continue
                    try:
                        amount = int(log.get("data", "0x0"), 16)
                        block = int(log.get("blockNumber", "0x0"), 16)
                    except ValueError:
                        continue
                    observed[tx] = {"tx": tx, "from": _topic_address(topics[1]).lower(),
                                    "amount": amount, "block": block}
                b = hi + 1

        by_tx = {p["tx"]: p for p in led.pending}
        for tx, entry in observed.items():
            if tx not in by_tx:                       # dedup by tx hash
                entry["seen_at"] = wall_now
                by_tx[tx] = entry

        # 2. prune: credited/flagged, already scanned past, or aged out.
        kept = []
        for p in by_tx.values():
            tx = p["tx"]
            settled = any(k.startswith(tx + ":") for k in led.seen)
            scanned_past = led.last_block and int(p.get("block", 0)) <= led.last_block
            if settled or scanned_past:
                continue                              # handed off cleanly
            if wall_now - int(p.get("seen_at", wall_now)) > cfg.pending_ttl_s:
                led.flag("stuck_pending",
                         f"payment {tx[:12]}… from {p.get('from','?')} seen but never "
                         f"credited within {cfg.pending_ttl_s}s — needs review",
                         token=None, tx=tx, sender=p.get("from", ""))
                continue
            kept.append(p)
        led.pending = kept
        return len(kept)

    def check_orphans(self, *, now: int | None = None) -> list[dict]:
        """Records carrying ACTIVE paid time whose token no longer EXISTS — the burn
        support case, made actionable.

        A holder can burn their own token (measured on the Studio collection), and if it
        carried unused paid time, that time is now attached to nothing and the money is
        spent. This finds those and alarms the OPERATOR. It never refunds and never edits
        a record: the alarm informs, the human decides. During the manual phase a refund
        of the unused portion is a courtesy of the early period — NOT a standing
        guarantee, because once the contract ships there is no refund path at all.

        BURNED vs NEVER-EXISTED. `ownerOf` reverts for both a burned id and one that was
        never minted, so reverting alone is not enough. Ids are issued contiguously from
        1, so an id at or below ever-minted WAS issued; if it now has no owner it was
        burned. An id above ever-minted never existed — a mistaken `grant`, most likely —
        and must NOT alarm, or the operator gets paged about tokens that never sold.
        """
        now = int(time.time()) if now is None else now
        active = [(int(k), v) for k, v in self.ledger.subs.items()
                  if int(v.get("paid_until", 0)) > now]
        if not active:
            return []
        ever = self.chain.highest_possible_id(self.cfg.nft_contract, "latest") or self.cfg.max_token_id
        owners = self.chain.owners_of(self.cfg.nft_contract, [t for t, _ in active], "latest")
        orphans = []
        for tid, rec in active:
            if tid in owners:                       # token still exists — fine
                continue
            if tid > ever:                          # never issued (bad grant) — not a burn
                continue
            remaining = int(rec["paid_until"]) - now
            orphans.append({"token": tid, "remaining_days": remaining // DAY,
                            "paid_until": int(rec["paid_until"]),
                            "last_payer": rec.get("last_payer", "")})
            if not self.ledger.has_open_flag("orphaned_paid_time", tid):
                self.ledger.flag(
                    "orphaned_paid_time",
                    f"token {tid} was BURNED with {remaining // DAY}d of paid time left "
                    f"(last paid by {rec.get('last_payer','?')}) — decide on a refund",
                    token=tid, remaining_days=remaining // DAY,
                    paid_until=int(rec["paid_until"]))
        return orphans

    def _credit(self, log: dict, stats: dict[str, int]) -> None:
        cfg, led = self.cfg, self.ledger
        key = f"{log.get('transactionHash')}:{log.get('logIndex')}"
        if key in led.seen:                       # RULE 3: idempotent
            stats["skipped"] += 1
            return

        topics = log.get("topics") or []
        if len(topics) < 3:
            led.seen.add(key)
            led.flag("malformed_log", "Transfer log without both indexed parties", tx=key)
            stats["flagged"] += 1
            return

        sender = _topic_address(topics[1]).lower()
        try:
            units = int(log.get("data", "0x0"), 16)
        except ValueError:
            led.seen.add(key)
            led.flag("malformed_log", "Transfer value is not a number", tx=key)
            stats["flagged"] += 1
            return

        # Mark seen BEFORE any decision: whatever happens below, this transfer must
        # never be considered twice.
        led.seen.add(key)

        # Ownership AND TIME are both taken AS OF THE PAYMENT'S BLOCK. Reading either at
        # scan time makes the result depend on when the watcher happened to run: ownership
        # would credit the wrong token after a transfer, and time would short a lapsed
        # renewer by the watcher's lag.
        block = log.get("blockNumber") or "latest"
        held = self._tokens_held(sender, block)
        paid_at = self.chain.block_timestamp(block)

        if not held:
            # Not a rejection — money genuinely arrived. A human decides whose it is.
            led.flag("payment_from_non_holder",
                     f"{sender} sent {units} units but held none of the collection at block {block}",
                     tx=key, sender=sender, units=units, block=block)
            stats["flagged"] += 1
            return

        if len(held) > 1:
            # WHICH token did they mean? Guessing would attach paid time to an asset the
            # payer may be about to sell. This is the one question only they can answer.
            led.flag("ambiguous_token",
                     f"{sender} sent {units} units but held tokens {held} — cannot tell which",
                     tx=key, sender=sender, units=units, tokens=held, block=block)
            stats["flagged"] += 1
            return

        token_id = held[0]
        months = units // cfg.price_units
        remainder = units - months * cfg.price_units      # RULE 2: round down
        if months <= 0:
            led.flag("underpayment",
                     f"{sender} sent {units} units for token {token_id}, "
                     f"under one month ({cfg.price_units})",
                     tx=key, sender=sender, units=units, token=token_id)
            stats["flagged"] += 1
            return

        led.extend(token_id, months * MONTH, paid_units=units, payer=sender, now=paid_at)
        stats["credited"] += 1
        if remainder:
            led.flag("overpayment_remainder",
                     f"{sender} sent {remainder} units beyond {months} whole month(s) "
                     f"for token {token_id}",
                     tx=key, sender=sender, units=units, token=token_id,
                     months=months, remainder=remainder)
            stats["flagged"] += 1


# ── operator entry point ─────────────────────────────────────────────────────
def _default_ledger_path(cfg: SubWatchConfig) -> str:
    # Where the ledger lives. cfg.ledger_path (PIKA_SUB_LEDGER) wins; otherwise a
    # per-user default. Plain JSON — safe to back up and to read.
    if cfg.ledger_path:
        return cfg.ledger_path
    env = os.environ.get("PIKA_SUB_LEDGER", "")
    return env if env else str(Path.home() / ".pika" / "subscriptions.json")


def _fmt(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(ts)) + "Z" if ts else "-"


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(
        prog="python -m server.subwatch",
        description="Semi-automated subscription tracking. Read-only on chain; "
                    "never signs, never holds a key, never revokes access.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("scan", help="one pass over new blocks, then exit")
    w = sub.add_parser("watch", help="scan on a loop")
    w.add_argument("--once", action="store_true", help="alias for scan")
    sub.add_parser("status", help="who is active, and for how long")
    f = sub.add_parser("flags", help="the review queue")
    f.add_argument("--all", action="store_true", help="include resolved")
    g = sub.add_parser("grant", help="manual override — comp, fix or extend by hand")
    g.add_argument("token_id", type=int, help="the NFT this time belongs to, not a wallet")
    g.add_argument("days", type=int)
    g.add_argument("--note", default="manual grant")
    o = sub.add_parser("orphans", help="active paid time on tokens that no longer exist (burned)")
    o.add_argument("--scan-first", action="store_true",
                   help="process new payments before checking, so a just-burned token is current")
    sub.add_parser("check", help="validate config and reach the chain, change nothing")

    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    # httpx/httpcore log every request at INFO as "HTTP Request: POST <url> ...", and the
    # RPC url embeds the provider API KEY in its path. Quiet them so a secret never reaches
    # a log file — the same reason gate._redact strips the url from our own log lines.
    for _n in ("httpx", "httpcore"):
        logging.getLogger(_n).setLevel(logging.WARNING)

    cfg = SubWatchConfig.from_env()
    ledger = Ledger.load(_default_ledger_path(cfg))

    if args.cmd == "status":
        act = ledger.active()
        print(f"ledger: {ledger.path}")
        print(f"last scanned block: {ledger.last_block}")
        print(f"active subscriptions: {len(act)}   open flags: "
              f"{sum(1 for f_ in ledger.flags if not f_.get('resolved'))}")
        for token_id, until in act:
            days = max(0, (until - int(time.time())) // DAY)
            payer = ledger.subs.get(token_id, {}).get("last_payer", "")
            print(f"  token #{token_id:<5} until {_fmt(until)}  ({days}d)"
                  + (f"   last paid by {payer}" if payer else ""))
        return 0

    if args.cmd == "flags":
        shown = [f_ for f_ in ledger.flags if args.all or not f_.get("resolved")]
        if not shown:
            print("no flags")
        for f_ in shown:
            print(f"  [{_fmt(f_['ts'])}] {f_['kind']}: {f_['detail']}")
        return 0

    if args.cmd == "grant":
        until = ledger.extend(args.token_id, args.days * DAY, note=args.note)
        ledger.save()
        print(f"token #{args.token_id} now paid until {_fmt(until)}")
        return 0

    cfg.validate()
    chain = Chain.from_env(cfg.chain_id)
    chain.assert_chain()

    if args.cmd == "check":
        head = chain.block_number()
        print(f"chain {cfg.chain_id} ok, head {head}, safe head {head - cfg.confirmations}")
        print(f"receiving {cfg.receiving}")
        print(f"pay token {cfg.pay_token} ({cfg.decimals} decimals, "
              f"{cfg.price_month}/month = {cfg.price_units} units)")
        top = chain.highest_possible_id(cfg.nft_contract, "latest")
        print(f"collection {cfg.nft_contract} "
              f"(ever-minted bound {top if top is not None else 'unknown — scanning to '
              + str(cfg.max_token_id)})")
        print(f"ledger {ledger.path} (last block {ledger.last_block})")
        return 0

    watcher = Watcher(cfg, chain, ledger)

    if args.cmd == "orphans":
        if getattr(args, "scan_first", False):
            watcher.scan_once()
        orphans = watcher.check_orphans()
        ledger.save()
        if not orphans:
            print("no orphaned paid time — every active subscription's token still exists")
            return 0
        print("BURNED TOKENS STILL CARRYING PAID TIME:\n")
        for o in orphans:
            print(f"  token #{o['token']}: {o['remaining_days']}d unused, "
                  f"paid_until {_fmt(o['paid_until'])}"
                  + (f", last paid by {o['last_payer']}" if o['last_payer'] else ""))
        print("\nManual phase only: you MAY refund the unused portion as a courtesy of the")
        print("early period. It is not a standing guarantee — once the contract ships there is")
        print("no refund path. Refund by hand; nothing here moves money.")
        return 0

    if args.cmd == "scan" or getattr(args, "once", False):
        stats = watcher.scan_once()
        stats["pending"] = watcher.scan_pending()
        stats["orphaned"] = len(watcher.check_orphans())
        ledger.save()
        print(json.dumps(stats))
        return 0

    _log.info("watching from block %s, every %ss", ledger.last_block or cfg.start_block, cfg.poll_s)
    while True:
        try:
            stats = watcher.scan_once()
            pending = watcher.scan_pending()
            orphans = watcher.check_orphans()
            if orphans:
                _log.warning("%d token(s) burned with active paid time — run `orphans`", len(orphans))
            if stats["credited"] or stats["flagged"] or orphans or pending:
                _log.info("scan %s pending=%d", stats, pending)
        except SubWatchError as e:
            # An RPC blip must not kill the watcher: the next pass resumes from the
            # last persisted block, so nothing is lost by simply trying again.
            _log.warning("scan failed, retrying: %s", e)
        time.sleep(cfg.poll_s)


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(main())
