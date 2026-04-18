"""Benchmark SPHINCS+ keygen / sign / verify across three configurations:

  baseline   — HashCtx OFF, ADRS_SNAPSHOT OFF  (pure re-init per hash call)
  opt123     — HashCtx ON,  ADRS_SNAPSHOT OFF  (pre-absorbed seed only)
  opt1234    — HashCtx ON,  ADRS_SNAPSHOT ON   (pre-absorbed seed + no adrs.copy())

Usage:
    python3 bench.py                         # quick run on sphincs-sha2-128s
    python3 bench.py --full                  # all SHA-2 sets
    python3 bench.py --sets sphincs-sha2-128s sphincs-sha2-192s
    python3 bench.py --iters-sign 10 --iters-verify 40
    python3 bench.py --profile               # cProfile top-20 for baseline sign
"""

from __future__ import annotations

import argparse
import cProfile
import pstats
import statistics
import time
from typing import Callable

import src.sphincs as sphincs_mod
import src.xmss as xmss_mod
from src.parameters import Parameters
from src.sphincs import spx_keygen, spx_sign, spx_verify

DEFAULT_SETS = ["sphincs-sha2-128s"]
FULL_SETS = [
    "sphincs-sha2-128s",
    "sphincs-sha2-128f",
    "sphincs-sha2-192s",
    "sphincs-sha2-192f",
    "sphincs-sha2-256s",
    "sphincs-sha2-256f",
]

CONFIGS = [
    ("baseline",  False, False),   # HashCtx off, ADRS_SNAPSHOT off
    ("opt123",    True,  False),   # HashCtx on,  ADRS_SNAPSHOT off
    ("opt1234",   True,  True),    # HashCtx on,  ADRS_SNAPSHOT on   ← Opt-4
]


def _median_ms(samples_ns: list[int]) -> tuple[float, float]:
    samples_ns = sorted(samples_ns)
    trimmed = samples_ns[1:-1] if len(samples_ns) >= 6 else samples_ns
    median = statistics.median(trimmed) / 1e6
    stdev = (statistics.stdev(trimmed) / 1e6) if len(trimmed) >= 2 else 0.0
    return median, stdev


def _time(fn: Callable, iters: int, warmup: int = 1) -> list[int]:
    for _ in range(warmup):
        fn()
    out = []
    for _ in range(iters):
        t0 = time.perf_counter_ns()
        fn()
        out.append(time.perf_counter_ns() - t0)
    return out


def _set_config(hashctx: bool, snapshot: bool) -> None:
    sphincs_mod.set_optimised(hashctx)
    xmss_mod.ADRS_SNAPSHOT = snapshot


def _run_set(name: str, iters_keygen: int, iters_sign: int, iters_verify: int) -> dict:
    params = Parameters.get_paramset(name)
    params.set_RANDOMIZE(False)

    # warm-up: generate a valid (sk, pk, sig) under full optimisations
    _set_config(True, True)
    sk, pk = spx_keygen(params)
    msg = b"benchmark message"
    sig = spx_sign(msg, sk, params)
    assert spx_verify(msg, sig, pk, params)

    results = {}
    for label, hashctx, snapshot in CONFIGS:
        _set_config(hashctx, snapshot)
        kg_ns   = _time(lambda: spx_keygen(params),              iters_keygen, warmup=1)
        sign_ns = _time(lambda: spx_sign(msg, sk, params),       iters_sign,   warmup=1)
        ver_ns  = _time(lambda: spx_verify(msg, sig, pk, params), iters_verify, warmup=2)
        results[label] = {
            "keygen": _median_ms(kg_ns),
            "sign":   _median_ms(sign_ns),
            "verify": _median_ms(ver_ns),
        }

    _set_config(True, True)
    return results


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sets", nargs="+")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--iters-keygen", type=int, default=3)
    parser.add_argument("--iters-sign",   type=int, default=5)
    parser.add_argument("--iters-verify", type=int, default=15)
    parser.add_argument("--profile", action="store_true")
    args = parser.parse_args()

    sets = args.sets or (FULL_SETS if args.full else DEFAULT_SETS)

    print("=" * 110)
    print(f"SPHINCS+ bench | iters: keygen={args.iters_keygen} sign={args.iters_sign} verify={args.iters_verify}")
    print(f"Configurations: baseline (no opts) | opt123 (HashCtx only) | opt1234 (HashCtx + Opt-4 ADRS snapshot)")
    print("=" * 110)

    all_results = {}
    for name in sets:
        print(f"\n  running {name} ...")
        r = _run_set(name, args.iters_keygen, args.iters_sign, args.iters_verify)
        all_results[name] = r
        for op in ("keygen", "sign", "verify"):
            base  = r["baseline"][op]
            o123  = r["opt123"][op]
            o1234 = r["opt1234"][op]
            sp123  = base[0] / o123[0]  if o123[0]  > 0 else float("inf")
            sp1234 = base[0] / o1234[0] if o1234[0] > 0 else float("inf")
            opt4_gain = o123[0] / o1234[0] if o1234[0] > 0 else float("inf")
            print(
                f"  {name:22s} {op:7s} "
                f"baseline={base[0]:8.2f}ms  "
                f"opt123={o123[0]:8.2f}ms ({sp123:.2f}x)  "
                f"opt1234={o1234[0]:8.2f}ms ({sp1234:.2f}x total, Opt-4 gain={opt4_gain:.3f}x)"
            )

    print("\n" + "=" * 110)
    print("SUMMARY TABLE")
    print("=" * 110)
    hdr = f"{'param set':22s} {'op':7s} {'baseline':>12s} {'opt123':>12s} {'opt1234':>12s} {'vs base':>8s} {'Opt-4 gain':>11s}"
    print(hdr)
    print("-" * len(hdr))
    for name, r in all_results.items():
        for op in ("keygen", "sign", "verify"):
            base  = r["baseline"][op][0]
            o123  = r["opt123"][op][0]
            o1234 = r["opt1234"][op][0]
            print(
                f"{name:22s} {op:7s} "
                f"{base:12.2f} {o123:12.2f} {o1234:12.2f} "
                f"{base/o1234:8.2f}x {o123/o1234:11.3f}x"
            )

    if args.profile:
        name = sets[0]
        params = Parameters.get_paramset(name)
        params.set_RANDOMIZE(False)
        _set_config(False, False)
        sk, pk = spx_keygen(params)
        msg = b"profile message"
        print("\n" + "=" * 110)
        print(f"cProfile: baseline spx_sign on {name} (top 20 cumulative)")
        print("=" * 110)
        pr = cProfile.Profile()
        pr.enable()
        spx_sign(msg, sk, params)
        pr.disable()
        pstats.Stats(pr).sort_stats("cumulative").print_stats(20)
        _set_config(True, True)


if __name__ == "__main__":
    main()
