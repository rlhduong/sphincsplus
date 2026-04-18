"""Benchmark SPHINCS+ keygen / sign / verify: baseline vs. HashCtx-optimised.

Usage:
    python bench.py                       # quick run on two parameter sets
    python bench.py --full                # all 128-bit + 192-bit sets
    python bench.py --sets sphincs-sha2-128s sphincs-sha2-128f
    python bench.py --iters-sign 5 --iters-verify 20

For every requested parameter set and operation (keygen / sign / verify) the
script runs the baseline path (pure re-init per hash call) and the optimised
path (pre-absorbed `HashCtx`) back-to-back with matched inputs and reports:

    baseline median ms,  optimised median ms,  speedup (baseline / optimised)

The `--profile` flag additionally prints a cProfile top-20 for signing on the
first parameter set, which is useful for confirming that hashlib dominates
the baseline run.
"""

from __future__ import annotations

import argparse
import cProfile
import pstats
import statistics
import time
from typing import Callable

import src.sphincs as sphincs_mod
from src.parameters import Parameters
from src.sphincs import spx_keygen, spx_sign, spx_verify


# Note: `sphincs-sha2-128f` and `sphincs-shake-128s` require an m-byte message
# digest that doesn't fit in the selected hash's output (pre-existing issue in
# the upstream implementation). We stick to parameter sets that actually work.
DEFAULT_SETS = ["sphincs-sha2-128s"]
FULL_SETS = [
    "sphincs-sha2-128s",
    "sphincs-sha2-128f",
    "sphincs-sha2-192s",
    "sphincs-sha2-192f",
    "sphincs-sha2-256s",
    "sphincs-sha2-256f",
]


def _median_ms(samples_ns: list[int]) -> tuple[float, float]:
    samples_ns = sorted(samples_ns)
    if len(samples_ns) >= 6:
        trimmed = samples_ns[1:-1]
    else:
        trimmed = samples_ns
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


def _run_set(name: str, iters_keygen: int, iters_sign: int, iters_verify: int) -> dict:
    params = Parameters.get_paramset(name)
    params.set_RANDOMIZE(False)  # deterministic signing -> stable timing

    sphincs_mod.set_optimised(True)
    sk, pk = spx_keygen(params)
    msg = b"benchmark message"
    sig = spx_sign(msg, sk, params)
    assert spx_verify(msg, sig, pk, params)

    results = {}
    for label, flag in [("baseline", False), ("optimised", True)]:
        sphincs_mod.set_optimised(flag)

        kg_ns = _time(lambda: spx_keygen(params), iters_keygen, warmup=1)
        sign_ns = _time(lambda: spx_sign(msg, sk, params), iters_sign, warmup=1)
        ver_ns = _time(lambda: spx_verify(msg, sig, pk, params), iters_verify, warmup=2)

        results[label] = {
            "keygen": _median_ms(kg_ns),
            "sign": _median_ms(sign_ns),
            "verify": _median_ms(ver_ns),
        }
    sphincs_mod.set_optimised(True)
    return results


def _fmt_row(name: str, op: str, base: tuple[float, float], opt: tuple[float, float]) -> str:
    base_med, base_sd = base
    opt_med, opt_sd = opt
    speedup = base_med / opt_med if opt_med > 0 else float("inf")
    return (
        f"{name:22s} {op:7s} "
        f"baseline={base_med:10.2f} ms (±{base_sd:6.2f})  "
        f"optimised={opt_med:10.2f} ms (±{opt_sd:6.2f})  "
        f"speedup={speedup:5.2f}x"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sets", nargs="+", help="parameter set names to benchmark")
    parser.add_argument("--full", action="store_true", help="run the full list of sets")
    parser.add_argument("--iters-keygen", type=int, default=3)
    parser.add_argument("--iters-sign", type=int, default=5)
    parser.add_argument("--iters-verify", type=int, default=15)
    parser.add_argument("--profile", action="store_true", help="cProfile first-set sign")
    args = parser.parse_args()

    sets = args.sets or (FULL_SETS if args.full else DEFAULT_SETS)

    print("=" * 100)
    print(f"SPHINCS+ bench | iters: keygen={args.iters_keygen} sign={args.iters_sign} verify={args.iters_verify}")
    print("=" * 100)

    all_results = {}
    for name in sets:
        print(f"\n  running {name} ...")
        r = _run_set(name, args.iters_keygen, args.iters_sign, args.iters_verify)
        all_results[name] = r
        for op in ("keygen", "sign", "verify"):
            print("  " + _fmt_row(name, op, r["baseline"][op], r["optimised"][op]))

    print("\n" + "=" * 100)
    print("SUMMARY TABLE")
    print("=" * 100)
    header = (
        f"{'parameter set':22s} {'op':7s} "
        f"{'baseline (ms)':>15s} {'optimised (ms)':>16s} {'speedup':>9s}"
    )
    print(header)
    print("-" * len(header))
    for name, r in all_results.items():
        for op in ("keygen", "sign", "verify"):
            base_med = r["baseline"][op][0]
            opt_med = r["optimised"][op][0]
            speedup = base_med / opt_med if opt_med > 0 else float("inf")
            print(
                f"{name:22s} {op:7s} "
                f"{base_med:15.2f} {opt_med:16.2f} {speedup:8.2f}x"
            )

    if args.profile:
        name = sets[0]
        params = Parameters.get_paramset(name)
        params.set_RANDOMIZE(False)
        sphincs_mod.set_optimised(False)
        sk, pk = spx_keygen(params)
        msg = b"profile message"
        print("\n" + "=" * 100)
        print(f"cProfile: baseline spx_sign on {name} (top 20 cumulative)")
        print("=" * 100)
        pr = cProfile.Profile()
        pr.enable()
        spx_sign(msg, sk, params)
        pr.disable()
        pstats.Stats(pr).sort_stats("cumulative").print_stats(20)
        sphincs_mod.set_optimised(True)


if __name__ == "__main__":
    main()
