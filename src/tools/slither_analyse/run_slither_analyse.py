import os
import re
import sys
import json
import time
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Tuple, List
sys.path.append(str(Path(__file__).resolve().parent.parent))
from paths import FLAT, RES
from colorama import init, Fore, Style
from tqdm import tqdm

init(autoreset=True)

# config
CHAIN = (sys.argv[1] if len(sys.argv) > 1 else "mainnet").strip().lower()

FLAT_DIR = FLAT / CHAIN
OUT_DIR  = RES / "slither" / CHAIN
OUT_DIR.mkdir(parents=True, exist_ok=True)

SUMMARY_CSV = OUT_DIR / "summary.csv"
FAILED_TXT  = OUT_DIR / "_failed.txt"
#########

# valid solc versions
VALID_SOLC_VERSIONS = [
    "0.4.1","0.4.2","0.4.5","0.4.6","0.4.7","0.4.8","0.4.9","0.4.10","0.4.11","0.4.12",
    "0.4.13","0.4.14","0.4.15","0.4.16","0.4.17","0.4.18","0.4.19","0.4.20","0.4.21",
    "0.4.22","0.4.23","0.4.24","0.4.25","0.4.26",
    "0.5.0","0.5.1","0.5.2","0.5.3","0.5.4","0.5.5","0.5.6","0.5.7","0.5.8","0.5.9","0.5.10","0.5.11","0.5.12","0.5.13","0.5.14","0.5.15","0.5.16","0.5.17",
    "0.6.0","0.6.1","0.6.2","0.6.3","0.6.4","0.6.5","0.6.6","0.6.7","0.6.8","0.6.9","0.6.10","0.6.11","0.6.12",
    "0.7.0","0.7.1","0.7.2","0.7.3","0.7.4","0.7.5","0.7.6",
    "0.8.0","0.8.1","0.8.2","0.8.3","0.8.4","0.8.5","0.8.6","0.8.7","0.8.8","0.8.9",
    "0.8.10","0.8.11","0.8.12","0.8.13","0.8.14","0.8.15","0.8.16","0.8.17","0.8.18","0.8.19","0.8.20","0.8.21","0.8.22","0.8.23","0.8.24","0.8.25","0.8.26","0.8.27","0.8.28","0.8.29","0.8.30"
]

ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
PRAGMA_RE = re.compile(r'^\s*pragma\s+solidity\s+([^;]+);', re.MULTILINE)

def vtuple(v: str) -> Tuple[int,int,int]:
    parts = v.strip().split(".")
    parts += ["0"]*(3-len(parts))
    return tuple(int(p) for p in parts[:3])

def normalize_version_tag(tag: str) -> Optional[str]:
    if not tag:
        return None
    tag = tag.strip()
    if tag.startswith("v"): tag = tag[1:]
    # strip build metadata/suffixes
    tag = re.split(r"[+-]", tag)[0]
    if re.fullmatch(r"\d+\.\d+", tag):
        tag += ".0"
    if not re.fullmatch(r"\d+\.\d+\.\d+", tag):
        return None
    return tag

def choose_best_match(target: str) -> Optional[str]:
    if target in VALID_SOLC_VERSIONS:
        return target
    maj,min,_ = vtuple(target)
    candidates = [v for v in VALID_SOLC_VERSIONS if vtuple(v)[:2] == (maj,min)]
    if candidates:
        return sorted(candidates, key=vtuple)[-1]
    return None

def parse_pragma_constraints(text: str) -> List[Tuple[str, str]]:
    m = PRAGMA_RE.search(text)
    if not m:
        return []
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

def satisfies(ver: str, constraints: List[Tuple[str,str]]) -> bool:
    vt = vtuple(ver)
    for op, c in constraints:
        ct = vtuple(c)
        if op == '^':
            if vt[0] != ct[0] or vt < ct:
                return False
        elif op == '=' and vt != ct:
            return False
        elif op == '>' and not (vt > ct):
            return False
        elif op == '>=' and not (vt >= ct):
            return False
        elif op == '<' and not (vt < ct):
            return False
        elif op == '<=' and not (vt <= ct):
            return False
    return True

def pick_version_from_pragma(sol_text: str) -> Optional[str]:
    cons = parse_pragma_constraints(sol_text)
    if not cons:
        return None
    matches = [v for v in VALID_SOLC_VERSIONS if satisfies(v, cons)]
    if not matches:
        return None
    return sorted(matches, key=vtuple)[-1]  # highest satisfying

def select_solc(version: str) -> bool:
    try:
        res = subprocess.run(
            ["solc-select", "use", version, "--always-install"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
        )
        tqdm.write(Fore.CYAN + f"    [solc] {res.stdout.strip() or 'selected'}")
        return True
    except subprocess.CalledProcessError as e:
        tqdm.write(Fore.RED + f"    [solc] Failed to use {version}: {e.stderr.strip() or e.stdout.strip()}")
        return False

def run_slither(sol_file: Path, out_json: Path, cwd: Path) -> Tuple[bool, str]:
    cmd = ["slither", str(sol_file.resolve()), "--json", str(out_json.resolve())]
    res = subprocess.run(cmd, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if out_json.exists() and out_json.stat().st_size > 0:
        return True, res.stdout.strip()
    return False, (res.stderr or res.stdout or "").strip()

def get_compiler_from_metadata(meta_path: Path) -> Optional[str]:
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        raw = meta.get("compiler_version") or ""
        return normalize_version_tag(raw)
    except Exception:
        return None

def main():
    if not FLAT_DIR.exists():
        print(Fore.RED + f"[!] Flattened directory not found: {FLAT_DIR}")
        sys.exit(1)

    # gather addresses
    targets = []
    for addr_dir in sorted(FLAT_DIR.iterdir()):
        if not addr_dir.is_dir(): continue
        addr = addr_dir.name.lower()
        if not ADDR_RE.fullmatch(addr):  # skip misc
            continue
        sol = addr_dir / f"{addr}.sol"
        if sol.exists():
            targets.append((addr, addr_dir, sol))

    if not targets:
        print(Fore.YELLOW + f"[i] No flattened contracts found under {FLAT_DIR}")
        return

    # prepare summary
    if not SUMMARY_CSV.exists():
        SUMMARY_CSV.write_text("address,solc_version,status,elapsed_sec,json_path,error\n", encoding="utf-8")
    failed_fh = FAILED_TXT.open("a", encoding="utf-8")

    ok = 0
    fail = 0

    tqdm.write(Fore.YELLOW + f"[+] Running Slither on {len(targets)} flattened contracts (chain={CHAIN})")
    with tqdm(total=len(targets), desc="Slither", unit="ct", dynamic_ncols=True) as pbar:
        for addr, addr_dir, sol_path in targets:
            pbar.set_postfix(addr=addr[:10]+"…", ok=ok, fail=fail)

            out_json = OUT_DIR / f"{addr}.json"
            meta_path = addr_dir / "metadata.json"

            try:
                # pick version
                chosen = get_compiler_from_metadata(meta_path)
                if not chosen:
                    # fallback to pragma in flattened file
                    text = sol_path.read_text(encoding="utf-8", errors="ignore")
                    chosen = pick_version_from_pragma(text)

                if not chosen:
                    tqdm.write(Fore.YELLOW + f"[i] {addr}: no compiler version found; will try Slither default")
                else:
                    # align chosen to available version
                    best = choose_best_match(chosen) or chosen
                    if not select_solc(best):
                        raise RuntimeError(f"could not select solc {best}")

                # run slither
                t0 = time.perf_counter()
                ok_run, msg = run_slither(sol_path, out_json, addr_dir)
                dt = time.perf_counter() - t0

                if ok_run:
                    tqdm.write(Fore.GREEN + f"[✓] {addr}: saved → {out_json.name} ({dt:.2f}s)")
                    ok += 1
                    with SUMMARY_CSV.open("a", encoding="utf-8") as fh:
                        fh.write(f"{addr},{best if chosen else ''},ok,{dt:.3f},{out_json},{''}\n")
                else:
                    tqdm.write(Fore.RED + f"[!] {addr}: Slither failed")
                    if msg:
                        # save stderr for inspection
                        (OUT_DIR / f"{addr}.stderr.txt").write_text(msg + "\n", encoding="utf-8")
                        tqdm.write(Fore.RED + "    ↪ " + msg.splitlines()[-1])
                    fail += 1
                    failed_fh.write(addr + "\n")
                    with SUMMARY_CSV.open("a", encoding="utf-8") as fh:
                        err_clean = msg.replace(",", " ").replace("\n", " ")[:500]
                        fh.write(f"{addr},{best if chosen else ''},fail,,,{err_clean}\n")

            except KeyboardInterrupt:
                tqdm.write(Fore.RED + "[!] Interrupted by user — partial results saved.")
                break
            except Exception as e:
                fail += 1
                emsg = str(e)
                tqdm.write(Fore.RED + f"[!] {addr}: {emsg}")
                (OUT_DIR / f"{addr}.stderr.txt").write_text(emsg + "\n", encoding="utf-8")
                failed_fh.write(addr + "\n")
                with SUMMARY_CSV.open("a", encoding="utf-8") as fh:
                    emsg_clean = emsg.replace(",", " ").replace("\n", " ")
                    fh.write(f"{addr},,error,,,{emsg_clean}\n")
            finally:
                pbar.set_postfix(addr=addr[:10]+"…", ok=ok, fail=fail)
                pbar.update(1)

    failed_fh.close()
    tqdm.write(Fore.GREEN + f"Done. Success: {ok}  " + Fore.RED + f"Failed: {fail}" + Style.RESET_ALL)

if __name__ == "__main__":
    main()
