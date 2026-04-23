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
    "sphincs-shake-128s",
    "sphincs-shake-128f",
    "sphincs-shake-192s",
    "sphincs-shake-192f",
    "sphincs-shake-256s",
    "sphincs-shake-256f",
]

CONFIGS = [
    ("baseline",  False, False),   # HashCtx off, ADRS_SNAPSHOT off
    ("opt123",    True,  False),   # HashCtx on,  ADRS_SNAPSHOT off
    ("opt1234",   True,  True),    # HashCtx on,  ADRS_SNAPSHOT on   ← Opt-4
]


def _median_ms(samples_ns: list[int]) -> tuple[float, float]:
    """Summarise raw nanosecond timing samples as (median_ms, stdev_ms).

    The slowest and fastest samples are trimmed when at least six are
    available to suppress one-off outliers (GC pauses, cold caches, etc.).
    Both the returned median and sample standard deviation are converted
    from nanoseconds to milliseconds. ``stdev`` is ``0.0`` when fewer than
    two (trimmed) samples remain.

    Args:
        samples_ns: Per-iteration timings expressed in nanoseconds.

    Returns:
        A ``(median_ms, stdev_ms)`` tuple. Both values are in milliseconds.
    """
    samples_ns = sorted(samples_ns)
    trimmed = samples_ns[1:-1] if len(samples_ns) >= 6 else samples_ns
    median = statistics.median(trimmed) / 1e6
    stdev = (statistics.stdev(trimmed) / 1e6) if len(trimmed) >= 2 else 0.0
    return median, stdev


def _time(fn: Callable, iters: int, warmup: int = 1) -> list[int]:
    """Time ``fn`` ``iters`` times with ``time.perf_counter_ns``.

    A small number of warm-up calls are issued first (results discarded) so
    that module-level caches (e.g. the pre-absorbed ``HashCtx``, ``Parameters``
    lookups, CPython inline caches) are populated before measurement begins.

    Args:
        fn: Zero-argument callable to benchmark.
        iters: Number of measured invocations to record.
        warmup: Number of un-measured invocations to issue first.

    Returns:
        A list of ``iters`` wall-clock durations in nanoseconds.
    """
    for _ in range(warmup):
        fn()
    out = []
    for _ in range(iters):
        t0 = time.perf_counter_ns()
        fn()
        out.append(time.perf_counter_ns() - t0)
    return out


def _set_config(hashctx: bool, snapshot: bool) -> None:
    """Toggle both benchmark-relevant optimisations at module scope.

    - ``hashctx`` flips ``src.sphincs.set_optimised``, which either installs
      or removes the pre-absorbed ``HashCtx`` used by ``h`` / ``prf``.
    - ``snapshot`` flips the ``src.xmss.ADRS_SNAPSHOT`` flag, which selects
      the ``h_adrs_bytes`` fast path (no per-call ``adrs.copy()``) over the
      original branch that copies the ``ADRS`` on every inner-node hash.

    Args:
        hashctx: Enable the pre-absorbed ``HashCtx`` optimisation.
        snapshot: Enable the ``ADRS`` snapshot (skip ``adrs.copy()``) path.
    """
    sphincs_mod.set_optimised(hashctx)
    xmss_mod.ADRS_SNAPSHOT = snapshot


def _run_set(name: str, iters_keygen: int, iters_sign: int, iters_verify: int) -> dict:
    """Benchmark a single parameter set across every configuration in ``CONFIGS``.

    A fresh ``(sk, pk)`` pair and signature are generated once under the fully
    optimised configuration and then reused for every measurement so that all
    three rows compare the *same* cryptographic work. Randomised signing is
    disabled so repeated ``spx_sign`` calls remain deterministic.

    Args:
        name: SPHINCS+ parameter-set name, e.g. ``"sphincs-sha2-128s"``.
        iters_keygen: Number of measured ``spx_keygen`` iterations per config.
        iters_sign: Number of measured ``spx_sign`` iterations per config.
        iters_verify: Number of measured ``spx_verify`` iterations per config.

    Returns:
        ``{config_label: {"keygen"|"sign"|"verify": (median_ms, stdev_ms)}}``
        for each entry in ``CONFIGS``.
    """
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


def _print_live_row(name: str, op: str, base: tuple, o123: tuple, o1234: tuple) -> None:
    """Stream one per-operation result line as measurements complete.

    Emits a compact ``name / op / baseline / opt123 (x) / opt1234 (x, Opt-4 x)``
    row to stdout so the user gets feedback during long ``--full`` runs, before
    the aggregate summary table is rendered.

    Args:
        name: Parameter-set label.
        op: Operation label (``"keygen"``, ``"sign"`` or ``"verify"``).
        base: ``(median_ms, stdev_ms)`` for the ``baseline`` config.
        o123: ``(median_ms, stdev_ms)`` for the ``opt123`` config.
        o1234: ``(median_ms, stdev_ms)`` for the ``opt1234`` config.
    """
    sp123     = base[0] / o123[0]  if o123[0]  > 0 else float("inf")
    sp1234    = base[0] / o1234[0] if o1234[0] > 0 else float("inf")
    opt4_gain = o123[0] / o1234[0] if o1234[0] > 0 else float("inf")
    print(
        f"  {name:22s} {op:7s} "
        f"baseline={base[0]:8.2f}ms  "
        f"opt123={o123[0]:8.2f}ms ({sp123:.2f}x)  "
        f"opt1234={o1234[0]:8.2f}ms ({sp1234:.2f}x total, Opt-4 gain={opt4_gain:.3f}x)"
    )


def _print_summary(all_results: dict) -> None:
    """Render the aggregate summary table grouped by parameter set.

    Each parameter set becomes its own small block: a bold header line, a
    three-row body (keygen / sign / verify) with millisecond medians for every
    configuration, and two derived speed-up columns. A legend is printed once
    at the end so the per-block rows stay narrow and readable.

    Layout (column widths in characters)::

        operation  baseline[ms]  opt123[ms]  opt1234[ms]  vs base  Opt-4 gain
        ---------  ------------  ----------  -----------  -------  ----------
        keygen         …              …            …         …x        …x
        sign           …              …            …         …x        …x
        verify         …              …            …         …x        …x

    Args:
        all_results: Mapping of parameter-set name to the ``_run_set`` output,
            i.e. ``{name: {config: {op: (median_ms, stdev_ms)}}}``.
    """
    col_op       = 10
    col_time     = 13
    col_speedup  =  9
    col_opt4     = 12
    row_width = col_op + 3 * col_time + col_speedup + col_opt4 + 4

    print("\n" + "=" * row_width)
    print("SUMMARY TABLE  (median wall time per call; lower is better)")
    print("=" * row_width)

    header = (
        f"{'operation':<{col_op}} "
        f"{'baseline[ms]':>{col_time}} "
        f"{'opt123[ms]':>{col_time}} "
        f"{'opt1234[ms]':>{col_time}} "
        f"{'vs base':>{col_speedup}} "
        f"{'Opt-4 gain':>{col_opt4}}"
    )

    for name, r in all_results.items():
        print(f"\n[{name}]")
        print(header)
        print("-" * row_width)
        for op in ("keygen", "sign", "verify"):
            base  = r["baseline"][op][0]
            o123  = r["opt123"][op][0]
            o1234 = r["opt1234"][op][0]
            vs_base  = (base / o1234) if o1234 > 0 else float("inf")
            opt4_gn  = (o123 / o1234) if o1234 > 0 else float("inf")
            print(
                f"{op:<{col_op}} "
                f"{base:>{col_time}.2f} "
                f"{o123:>{col_time}.2f} "
                f"{o1234:>{col_time}.2f} "
                f"{vs_base:>{col_speedup - 1}.2f}x "
                f"{opt4_gn:>{col_opt4 - 1}.3f}x"
            )

    print("\n" + "-" * row_width)
    print("Legend:")
    print("  baseline   : HashCtx OFF, ADRS_SNAPSHOT OFF  (reference impl.)")
    print("  opt123     : HashCtx ON,  ADRS_SNAPSHOT OFF  (Opts 1-3 only)")
    print("  opt1234    : HashCtx ON,  ADRS_SNAPSHOT ON   (Opts 1-3 + Opt-4)")
    print("  vs base    : baseline / opt1234   (total speed-up factor)")
    print("  Opt-4 gain : opt123   / opt1234   (marginal gain from Opt-4 alone)")
    print("=" * row_width)


def _run_profile(set_name: str) -> None:
    """Profile one ``spx_sign`` call on ``set_name`` under the baseline config.

    Disables both optimisations, generates a deterministic key pair, then
    wraps a single ``spx_sign`` in ``cProfile`` and prints the top 20 entries
    ordered by cumulative time. Optimisations are restored before returning
    so any later benchmark work runs with full performance.

    Args:
        set_name: Parameter-set name to profile, e.g. ``"sphincs-sha2-128s"``.
    """
    params = Parameters.get_paramset(set_name)
    params.set_RANDOMIZE(False)
    _set_config(False, False)
    sk, _pk = spx_keygen(params)
    msg = b"profile message"
    print("\n" + "=" * 110)
    print(f"cProfile: baseline spx_sign on {set_name} (top 20 cumulative)")
    print("=" * 110)
    pr = cProfile.Profile()
    pr.enable()
    spx_sign(msg, sk, params)
    pr.disable()
    pstats.Stats(pr).sort_stats("cumulative").print_stats(20)
    _set_config(True, True)


def main() -> None:
    """CLI entry point.

    Parses command-line flags, runs ``_run_set`` for each requested parameter
    set while streaming per-operation rows through ``_print_live_row``, prints
    the aggregated summary via ``_print_summary``, and optionally launches a
    ``cProfile`` session on the first parameter set when ``--profile`` is set.

    Supported flags:
        --sets NAME [NAME ...]   Explicit list of parameter-set names.
        --full                   Shortcut for every entry in ``FULL_SETS``.
        --iters-keygen N         Measured keygen iterations per config (default 3).
        --iters-sign N           Measured sign iterations per config   (default 5).
        --iters-verify N         Measured verify iterations per config (default 15).
        --profile                Append a cProfile top-20 dump for baseline sign.
    """
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
    print("Configurations: baseline (no opts) | opt123 (HashCtx only) | opt1234 (HashCtx + Opt-4 ADRS snapshot)")
    print("=" * 110)

    all_results: dict = {}
    for name in sets:
        print(f"\n  running {name} ...")
        r = _run_set(name, args.iters_keygen, args.iters_sign, args.iters_verify)
        all_results[name] = r
        for op in ("keygen", "sign", "verify"):
            _print_live_row(name, op, r["baseline"][op], r["opt123"][op], r["opt1234"][op])

    _print_summary(all_results)

    if args.profile:
        _run_profile(sets[0])


if __name__ == "__main__":
    main()
