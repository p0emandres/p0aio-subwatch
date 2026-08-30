#!/usr/bin/env python3
"""Mutation gate for subwatch.py.

subwatch is money-adjacent accounting: it reads USDC payments and decides who has paid
access time. A green test suite is not enough — the suite must BITE. This harness breaks
one security-relevant guard at a time, runs the suite, and demands a test NOTICES. A
test failure = mutant KILLED (good). A SURVIVOR (suite still green while the code is
wrong) is a real gap in coverage — fix the test, not the mutant.

    python3 tests/mutate_subwatch.py

Rewrites subwatch.py IN PLACE while it runs; restores after every mutant, with a
belt-and-braces restore in `finally`. Run it on a clean checkout so a crash cannot lose
work (the diff after a clean run must be empty). Add a mutant here whenever you add a
guard to subwatch worth trusting.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
TARGET = os.path.join(REPO, "subwatch.py")
SUITES = ["tests/test_subwatch.py", "tests/test_access_state.py"]

# (label, exact_old, mutated_new) — each breaks ONE load-bearing guard. Keep `old`
# verbatim and unique enough that .replace(count=1) hits the intended line.
MUTANTS = [
    ("is_paid: active-check inverted (> -> <)",
     "return self.paid_until(token_id) > (int(time.time()) if now is None else now)",
     "return self.paid_until(token_id) < (int(time.time()) if now is None else now)"),
    ("extend: RULE 1 forward-only broken (max -> min)",
     "base = max(int(rec.get(\"paid_until\", 0)), now)",
     "base = min(int(rec.get(\"paid_until\", 0)), now)"),
    ("credit: RULE 3 idempotency disabled (in -> not in)",
     "if key in led.seen:",
     "if key not in led.seen:"),
    ("scan: reorg cushion removed (head - conf -> head + conf)",
     "safe_head = head - cfg.confirmations",
     "safe_head = head + cfg.confirmations"),
    ("credit: non-holder guard inverted (not held -> held)",
     "if not held:",
     "if held:"),
    ("credit: ambiguous multi-token guard defeated (>1 -> <1)",
     "if len(held) > 1:",
     "if len(held) < 1:"),
    ("credit: underpayment guard weakened (<=0 -> <0)",
     "if months <= 0:",
     "if months < 0:"),
    ("credit: RULE 2 round-down over-credits by a month (+1)",
     "months = units // cfg.price_units",
     "months = units // cfg.price_units + 1"),
]


def run_suites() -> bool:
    """True = every suite passed (mutant SURVIVED); False = a suite failed (KILLED)."""
    env = dict(os.environ, PYTHONPATH=REPO)
    for s in SUITES:
        r = subprocess.run([sys.executable, s], cwd=REPO, env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if r.returncode != 0:
            return False
    return True


def main() -> int:
    original = open(TARGET, encoding="utf-8").read()
    if not run_suites():
        print("BASELINE FAILS — a mutation gate proves nothing over a red suite.")
        return 2
    print("baseline: all suites GREEN\n")
    killed = survived = invalid = 0
    try:
        for label, old, new in MUTANTS:
            if old not in original:
                print(f"  INVALID   {label}\n            (pattern not found — the line changed; fix this mutant)")
                invalid += 1
                continue
            open(TARGET, "w", encoding="utf-8").write(original.replace(old, new, 1))
            passed = run_suites()
            open(TARGET, "w", encoding="utf-8").write(original)  # restore at once
            if passed:
                print(f"  SURVIVED  {label}   <-- GAP: no test caught this")
                survived += 1
            else:
                print(f"  killed    {label}")
                killed += 1
    finally:
        open(TARGET, "w", encoding="utf-8").write(original)  # belt: always restore
    print(f"\n{'PASS' if survived == 0 else 'GAPS FOUND'} — "
          f"{killed} killed · {survived} survived · {invalid} invalid  (of {len(MUTANTS)})")
    return 0 if survived == 0 and invalid == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
