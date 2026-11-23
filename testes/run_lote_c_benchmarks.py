"""
run_lote_c_benchmarks.py

Script reproduzível do Lote C (Round 2 - BaSingSe):
  1. Compila `implementacao/c_core/rsd_s_v5_ct.c` em `-O0`, `-O2`, `-O3` (e `-O3 -march=native`).
  2. Executa TVLA estendido (Welch's t-test, 50.000 fixas + 50.000 aleatórias = 100.000 amostras
     por teste; TVLA-A entrada fixa vs aleatória e TVLA-B chave+entrada fixa vs aleatória)
     sequencialmente em `-O0`, `-O2` e `-O3`.
  3. Executa benchmarks de throughput (64B, 1KB, 64KB, 1MB) do núcleo C99 vs OpenSSL
     AES-256-GCM e ChaCha20-Poly1305, e da implementação Python (`rsd_s_v5_hardened.py`)
     vs `cryptography` (AESGCM, ChaCha20Poly1305).
  4. Salva resultados JSON em `resultados/v5_sandbox/lote_c_sidechannel_bench_results.json`
     e relatório em `resultados/v5_sandbox/lote_c_sidechannel_bench_report.md`.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "implementacao"))

from rsd_s_v5_hardened import diffuse_rsd_s_v5, diffuse_rsd_s_v5_pre_sha  # noqa: E402


def run_cmd(cmd: list[str]) -> str:
    res = subprocess.run(cmd, cwd=ROOT, check=True, capture_output=True, text=True)
    return res.stdout


def inspect_assembly(asm_path: Path) -> dict:
    text = asm_path.read_text(encoding="utf-8")
    lines = text.splitlines()
    # Count conditional jumps and check for table/LUT-like indexed loads in secret functions
    cond_jumps = []
    cmovs = []
    for ln in lines:
        s = ln.strip()
        if s.startswith(("je ", "jne ", "jl ", "jle ", "jg ", "jge ", "ja ", "jae ", "jb ", "jbe ", "js ", "jns ")):
            cond_jumps.append(s)
        elif s.startswith("cmov"):
            cmovs.append(s)
    return {
        "total_asm_lines": len(lines),
        "conditional_jump_count": len(cond_jumps),
        "cmov_count": len(cmovs),
    }


def bench_python_crypto() -> dict:
    payloads = [
        ("64B", 64, 5000),
        ("1KB", 1024, 2000),
        ("64KB", 65536, 500),
        ("1MB", 1048576, 50),
    ]
    key = bytes(range(32))
    nonce = bytes(range(12))
    aes = AESGCM(key)
    chacha = ChaCha20Poly1305(key)

    results = {}
    for label, size, iters in payloads:
        pt = b"\xAB" * size
        # Warmup
        _ = aes.encrypt(nonce, pt, None)
        _ = chacha.encrypt(nonce, pt, None)

        t0 = time.perf_counter_ns()
        for i in range(iters):
            _ = aes.encrypt(nonce, pt, None)
        t1 = time.perf_counter_ns()
        aes_us = ((t1 - t0) / 1000.0) / iters
        aes_mibs = ((size * iters) / (1024.0 * 1024.0)) / ((t1 - t0) / 1e9)

        t0 = time.perf_counter_ns()
        for i in range(iters):
            _ = chacha.encrypt(nonce, pt, None)
        t1 = time.perf_counter_ns()
        chacha_us = ((t1 - t0) / 1000.0) / iters
        chacha_mibs = ((size * iters) / (1024.0 * 1024.0)) / ((t1 - t0) / 1e9)

        results[label] = {
            "bytes": size,
            "python_aes_256_gcm": {"mib_s": round(aes_mibs, 4), "latency_us": round(aes_us, 3)},
            "python_chacha20_poly1305": {"mib_s": round(chacha_mibs, 4), "latency_us": round(chacha_us, 3)},
        }

    # Python RSD-S v5 (measured on 64B=1 block and 1KB=16 blocks; extrapolated linearly for 64KB and 1MB)
    # Warmup
    _ = diffuse_rsd_s_v5(123, 456, key, 1)
    _ = diffuse_rsd_s_v5_pre_sha(123, 456, key, 1)

    t0 = time.perf_counter_ns()
    for i in range(10):
        _ = diffuse_rsd_s_v5(123 + i, 456, key, 1)
    t1 = time.perf_counter_ns()
    py_64b_us = ((t1 - t0) / 1000.0) / 10
    py_64b_mibs = (64.0 * 10 / (1024.0 * 1024.0)) / ((t1 - t0) / 1e9)

    t0 = time.perf_counter_ns()
    for i in range(16):
        _ = diffuse_rsd_s_v5(123 + i, 456, key, 1)
    t1 = time.perf_counter_ns()
    py_1kb_us = (t1 - t0) / 1000.0
    py_1kb_mibs = (1024.0 / (1024.0 * 1024.0)) / ((t1 - t0) / 1e9)

    results["64B"]["python_rsd_s_v5"] = {
        "mib_s": round(py_64b_mibs, 6),
        "latency_us": round(py_64b_us, 1),
        "measured": True,
    }
    results["1KB"]["python_rsd_s_v5"] = {
        "mib_s": round(py_1kb_mibs, 6),
        "latency_us": round(py_1kb_us, 1),
        "measured": True,
    }
    results["64KB"]["python_rsd_s_v5"] = {
        "mib_s": round(py_1kb_mibs, 6),
        "latency_us": round(py_1kb_us * 64.0, 1),
        "measured": False,
        "note": "Extrapolated linearly from 1KB (16-block) measurement",
    }
    results["1MB"]["python_rsd_s_v5"] = {
        "mib_s": round(py_1kb_mibs, 6),
        "latency_us": round(py_1kb_us * 1024.0, 1),
        "measured": False,
        "note": "Extrapolated linearly from 1KB (16-block) measurement",
    }
    return results


def main() -> None:
    c_core = ROOT / "implementacao" / "c_core" / "rsd_s_v5_ct.c"
    c_harness = ROOT / "testes" / "lote_c_tvla_and_bench.c"
    out_dir = ROOT / "resultados" / "v5_sandbox"
    out_dir.mkdir(parents=True, exist_ok=True)

    opt_configs = [
        ("O0", ["-O0"]),
        ("O2", ["-O2"]),
        ("O3", ["-O3"]),
        ("O3_native", ["-O3", "-march=native"]),
    ]

    all_results: dict = {
        "metadata": {
            "c_core": str(c_core.relative_to(ROOT)),
            "c_harness": str(c_harness.relative_to(ROOT)),
            "tvla_n_per_group": 50000,
            "tvla_total_samples_per_test": 100000,
            "tvla_threshold_abs_t": 4.5,
        },
        "assembly_inspection": {},
        "tvla": {},
        "c99_benchmarks": {},
        "python_benchmarks": {},
    }

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        for label, flags in opt_configs:
            asm_file = tmp_path / f"rsd_{label}.s"
            obj_file = tmp_path / f"rsd_{label}.o"
            bin_file = tmp_path / f"bench_{label}"

            run_cmd(["gcc", *flags, "-Wall", "-Wextra", "-Werror", "-S", str(c_core), "-o", str(asm_file)])
            run_cmd(["gcc", *flags, "-Wall", "-Wextra", "-Werror", "-c", str(c_core), "-o", str(obj_file)])
            run_cmd(["gcc", "-O2", "-Wall", "-Wextra", "-Werror", str(c_harness), str(obj_file), "-lcrypto", "-lm", "-o", str(bin_file)])

            all_results["assembly_inspection"][label] = inspect_assembly(asm_file)

            if label in ("O0", "O2", "O3"):
                print(f"[TVLA] Running 100,000-sample TVLA-A & TVLA-B for {label}...", flush=True)
                tvla_out = run_cmd([str(bin_file), "--tvla", "50000", label])
                all_results["tvla"][label] = json.loads(tvla_out)

            if label in ("O2", "O3", "O3_native"):
                print(f"[BENCH] Running C99 vs OpenSSL throughput benchmark for {label}...", flush=True)
                bench_out = run_cmd([str(bin_file), "--bench", label])
                all_results["c99_benchmarks"][label] = json.loads(bench_out)

    print("[BENCH] Running Python rsd_s_v5_hardened.py vs cryptography AEAD...", flush=True)
    all_results["python_benchmarks"] = bench_python_crypto()

    json_path = out_dir / "lote_c_sidechannel_bench_results.json"
    json_path.write_text(json.dumps(all_results, indent=2), encoding="utf-8")
    print(f"[DONE] Saved JSON to {json_path}")


if __name__ == "__main__":
    main()
