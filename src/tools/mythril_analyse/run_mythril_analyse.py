import sys, re, json, time, subprocess, argparse
from pathlib import Path
from typing import Optional, Tuple, List
sys.path.append(str(Path(__file__).resolve().parent.parent))
from paths import FLAT, RES
from filelock import FileLock
from colorama import init, Fore, Style
from tqdm import tqdm
init(autoreset=True)

parser = argparse.ArgumentParser(description="Run Mythril on all flattened contracts")
parser.add_argument("--timeout", type=int, default=60, help="Execution timeout per contract (sec)")
parser.add_argument("--depth", type=int, default=32, help="Max symbolic execution depth")
args = parser.parse_args()

CHAIN = "mainnet"
EXEC_TIMEOUT_SEC = int(args.timeout)
MAX_DEPTH = int(args.depth)

# Directories
FLAT_DIR = FLAT / CHAIN
OUT_BASE = RES / "mythril"
OUT_DIR  = OUT_BASE / CHAIN
OUT_DIR.mkdir(parents=True, exist_ok=True)

SUMMARY_CSV = OUT_DIR / "summary.csv"
FAILED_TXT  = OUT_DIR / "_failed.txt"

ADDR_RE   = re.compile(r"^0x[a-fA-F0-9]{40}$")
PRAGMA_RE = re.compile(r'^\s*pragma\s+solidity\s+([^;]+);', re.MULTILINE)

VALID_SOLC_VERSIONS = [
    "0.4.11","0.4.12","0.4.13","0.4.14","0.4.15","0.4.16","0.4.17","0.4.18","0.4.19","0.4.20","0.4.21","0.4.22","0.4.23","0.4.24","0.4.25","0.4.26",
    "0.5.0","0.5.1","0.5.2","0.5.3","0.5.4","0.5.5","0.5.6","0.5.7","0.5.8","0.5.9","0.5.10","0.5.11","0.5.12","0.5.13","0.5.14","0.5.15","0.5.16","0.5.17",
    "0.6.0","0.6.1","0.6.2","0.6.3","0.6.4","0.6.5","0.6.6","0.6.7","0.6.8","0.6.9","0.6.10","0.6.11","0.6.12",
    "0.7.0","0.7.1","0.7.2","0.7.3","0.7.4","0.7.5","0.7.6",
    "0.8.0","0.8.1","0.8.2","0.8.3","0.8.4","0.8.5","0.8.6","0.8.7","0.8.8","0.8.9",
    "0.8.10","0.8.11","0.8.12","0.8.13","0.8.14","0.8.15","0.8.16","0.8.17","0.8.18","0.8.19","0.8.20","0.8.21","0.8.22","0.8.23","0.8.24","0.8.25","0.8.26","0.8.27","0.8.28","0.8.29","0.8.30"
]

def vtuple(v: str):
    p = v.split("."); p += ["0"]*(3-len(p)); return tuple(int(x) for x in p[:3])

def normalize_version_tag(tag: str) -> Optional[str]:
    if not tag: return None
    t = tag.strip()
    if t.startswith("v"): t = t[1:]
    t = re.split(r"[+-]", t)[0]
    if re.fullmatch(r"\d+\.\d+", t): t += ".0"
    return t if re.fullmatch(r"\d+\.\d+\.\d+", t) else None

def choose_best_match(target: str) -> Optional[str]:
    if target in VALID_SOLC_VERSIONS: return target
    maj, min, _ = vtuple(target)
    cands = [v for v in VALID_SOLC_VERSIONS if vtuple(v)[:2] == (maj,min)]
    return sorted(cands, key=vtuple)[-1] if cands else None

def parse_pragma_constraints(text: str):
    m = PRAGMA_RE.search(text)
    if not m: return []
    clause = m.group(1)
    parts = re.split(r'\s+', clause.strip())
    out = []
    for part in parts:
        if not part: continue
        if re.match(r'^\d+\.\d+(?:\.\d+)?$', part):
            part = '=' + (part if part.count('.')==2 else part + '.0')
        mo = re.match(r'^(\^|=|>=|<=|>|<)\s*(\d+\.\d+(?:\.\d+)?)$', part)
        if not mo: continue
        op, ver = mo.groups()
        if ver.count(".")==1: ver += ".0"
        out.append((op, ver))
    return out

def satisfies(ver: str, cons) -> bool:
    vt = vtuple(ver)
    for op, c in cons:
        ct = vtuple(c)
        if op == '^':
            if vt[0] != ct[0] or vt < ct: return False
        elif op == '=' and vt != ct: return False
        elif op == '>' and not (vt > ct): return False
        elif op == '>=' and not (vt >= ct): return False
        elif op == '<' and not (vt < ct): return False
        elif op == '<=' and not (vt <= ct): return False
    return True

def pick_version_from_pragma(sol_text: str) -> Optional[str]:
    cons = parse_pragma_constraints(sol_text)
    if not cons: return None
    matches = [v for v in VALID_SOLC_VERSIONS if satisfies(v, cons)]
    return sorted(matches, key=vtuple)[-1] if matches else None

def get_compiler_from_metadata(meta_path: Path) -> Optional[str]:
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        raw = meta.get("compiler_version") or ""
        return normalize_version_tag(raw)
    except Exception:
        return None

SOLC_LOCK = Path(".solc-select.lock")  # lives in repo root

def select_solc(version: str) -> bool:
    try:
        with FileLock(str(SOLC_LOCK)):
            res = subprocess.run(
                ["solc-select", "use", version, "--always-install"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
            )
        tqdm.write(Fore.CYAN + f"    [solc] {version} selected")
        return True
    except subprocess.CalledProcessError as e:
        tqdm.write(Fore.RED + f"    [solc] Failed to use {version}: {(e.stderr or e.stdout).strip()}")
        return False

def run_mythril(sol_file: Path, workdir: Path) -> Tuple[bool, str, str]:
    cmd = [
        "myth", "analyze", str(sol_file.resolve()),
        "-o", "json",
        "--execution-timeout", str(EXEC_TIMEOUT_SEC),
        "--max-depth", str(MAX_DEPTH)
    ]

    t0 = time.perf_counter()
    try:
        res = subprocess.run(
            cmd,
            cwd=str(workdir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        dt = time.perf_counter() - t0
        out = (res.stdout or "").strip()
        if out.startswith("{") or out.startswith("["):
            status = "partial" if dt >= (EXEC_TIMEOUT_SEC - 1) else "ok"
            return True, out, status
        else:
            return False, (res.stderr or res.stdout or "").strip(), "fail"
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "").strip()
        if out.startswith("{") or out.startswith("["):
            return True, out, "partial"
        return False, (e.stderr or out or "timeout"), "fail"


def main():
    if not FLAT_DIR.exists():
        tqdm.write(Fore.RED + f"[!] Flattened directory not found: {FLAT_DIR}")
        sys.exit(1)

    allowlist: Optional[set[str]] = None

    targets = []
    for addr_dir in sorted(FLAT_DIR.iterdir()):
        if not addr_dir.is_dir(): continue
        addr = addr_dir.name.lower()
        if not re.fullmatch(r"0x[a-fA-F0-9]{40}", addr): continue
        if allowlist and addr not in allowlist: continue
        sol = addr_dir / f"{addr}.sol"
        if sol.exists():
            targets.append((addr, addr_dir, sol))

    if not targets:
        tqdm.write(Fore.YELLOW + f"[i] No flattened contracts found under {FLAT_DIR}")
        return

    if not SUMMARY_CSV.exists():
        SUMMARY_CSV.write_text("address,solc_version,status,elapsed_sec,json_path,error\n", encoding="utf-8")
    failed_fh = FAILED_TXT.open("a", encoding="utf-8")

    ok = partial = fail = skipped = 0
    tqdm.write(
        Fore.YELLOW
        + f"[+] Mythril on {len(targets)} contracts  "
        + f"(chain={CHAIN}, out={OUT_DIR.name}, timeout={EXEC_TIMEOUT_SEC}s, depth={MAX_DEPTH}"
    )

    with tqdm(total=len(targets), desc="Mythril", unit="ct", dynamic_ncols=True) as pbar:
        for addr, addr_dir, sol_path in targets:
            out_json = OUT_DIR / f"{addr}.json"
            if out_json.exists():
                skipped += 1
                pbar.update(1)
                pbar.set_postfix(addr=addr[:10]+"…", ok=ok, partial=partial, fail=fail, skipped=skipped)
                continue

            pbar.set_postfix(addr=addr[:10]+"…", ok=ok, partial=partial, fail=fail, skipped=skipped)
            meta_path = addr_dir / "metadata.json"

            try:
                chosen = get_compiler_from_metadata(meta_path)
                if not chosen:
                    txt = sol_path.read_text(encoding="utf-8", errors="ignore")
                    chosen = pick_version_from_pragma(txt)
                best = choose_best_match(chosen) if chosen else None
                if best and not select_solc(best):
                    raise RuntimeError(f"could not select solc {best}")

                t0 = time.perf_counter()
                ok_run, payload, status_tag = run_mythril(sol_path, addr_dir)
                dt = time.perf_counter() - t0

                if ok_run:
                    out_json.parent.mkdir(parents=True, exist_ok=True)
                    out_json.write_text(payload + "\n", encoding="utf-8")

                    if status_tag == "ok":
                        ok += 1
                        tqdm.write(Fore.GREEN + f"[✓] {addr}: saved → {out_json.name} ({dt:.2f}s)")
                    else:
                        partial += 1
                        tqdm.write(Fore.YELLOW + f"[~] {addr}: timeout — saved partial → {out_json.name} ({dt:.2f}s)")

                    with SUMMARY_CSV.open("a", encoding="utf-8") as fh:
                        fh.write(f"{addr},{best or ''},{status_tag},{dt:.3f},{out_json},\n")
                else:
                    fail += 1
                    msg = payload
                    (OUT_DIR / f"{addr}.stderr.txt").write_text(msg + "\n", encoding="utf-8")
                    last = msg.splitlines()[-1] if '\n' in msg else msg
                    tqdm.write(Fore.RED + f"[!] {addr}: Mythril failed\n    ↪ {last}")
                    failed_fh.write(addr + "\n")
                    err_clean = (msg or "").replace(",", " ").replace("\n", " ")[:500]
                    with SUMMARY_CSV.open("a", encoding="utf-8") as fh:
                        fh.write(f"{addr},{best or ''},fail,,,{err_clean}\n")

            except KeyboardInterrupt:
                tqdm.write(Fore.RED + "[!] Interrupted by user — partial results saved.")
                break
            except Exception as e:
                fail += 1
                emsg = str(e)
                (OUT_DIR / f"{addr}.stderr.txt").write_text(emsg + "\n", encoding="utf-8")
                failed_fh.write(addr + "\n")
                emsg_clean = emsg.replace(",", " ").replace("\n", " ")
                with SUMMARY_CSV.open("a", encoding="utf-8") as fh:
                    fh.write(f"{addr},,error,,,{emsg_clean}\n")
                tqdm.write(Fore.RED + f"[!] {addr}: {emsg}")
            finally:
                pbar.set_postfix(addr=addr[:10]+"…", ok=ok, partial=partial, fail=fail, skipped=skipped)
                pbar.update(1)

    failed_fh.close()
    tqdm.write(
        Fore.GREEN + f"Done. OK: {ok}  "
        + Fore.YELLOW + f"Partial: {partial}  "
        + Fore.RED + f"Failed: {fail}  "
        + Style.RESET_ALL + f"Skipped: {skipped}"
    )

if __name__ == "__main__":
    main()
