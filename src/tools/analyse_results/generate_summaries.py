import csv
import json
from pathlib import Path
from typing import Dict, List
from colorama import init, Fore, Style

init(autoreset=True)

ROOT = Path(__file__).resolve().parents[3]
DATA = ROOT / "data" / "results"
SLITHER_DIR = DATA / "slither" / "mainnet"
MYTHRIL_DIR = DATA / "mythril" / "mainnet"

SLITHER_SUMMARY_IN = SLITHER_DIR / "summary.csv"
MYTHRIL_SUMMARY_IN = MYTHRIL_DIR / "summary.csv"

# Output filenames
OUT_DIR = ROOT / "reports"
SLITHER_SUMMARY_OUT = OUT_DIR / "slither_summary_swc.csv"
MYTHRIL_SUMMARY_OUT = OUT_DIR / "mythril_summary_swc.csv"

OVERLAP_SUMMARY_OUT = OUT_DIR / "overlap_summary_swc.csv"

# columns
SWC_MIN = 100
SWC_MAX = 136
SWC_COLS = [f"SWC-{i}" for i in range(SWC_MIN, SWC_MAX + 1)]
OUTPUT_COLUMNS = ["address"] + SWC_COLS + ["solc_version", "status", "elapsed_sec"]

SLITHER_TO_SWC: Dict[str, int] = {
    "reentrancy-eth": 107,
    "arbitrary-send-eth": 105,
    "uninitialized-state": 109,
    "shadowing-state": 119,
    "controlled-delegatecall": 106,
    "uninitialized-storage": 109,
    "suicidal": 106,
    "reentrancy-benign": 107,
    "reentrancy-no-eth": 107,
    "shadowing-abstract": 119,
    "shadowing-local": 119,
    "tx-origin": 115,
    "unused-return": 104,
}

# helpers
def zero_counts() -> Dict[str, int]:
    return {col: 0 for col in SWC_COLS}

def safe_json_load(p: Path):
    try:
        with p.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(Fore.RED + f"[!] Failed to read JSON: {p} ({e})")
        return None

def extract_swc_id_from_string(s: str) -> int:
    s_up = s.upper()
    idx = s_up.find("SWC-")
    if idx >= 0:
        digits = []
        for ch in s_up[idx+4:idx+8]:
            if ch.isdigit():
                digits.append(ch)
            else:
                break
        if digits:
            try:
                return int("".join(digits))
            except ValueError:
                return -1
    return -1

def find_json_path(tool_dir: Path, address: str, json_path_value: str) -> Path:
    if json_path_value:
        jp = Path(json_path_value)
        if not jp.is_absolute() and (str(jp).startswith("data/") or str(jp).startswith("data\\")):
            jp = ROOT / jp
        if jp.exists():
            return jp

    fallback = tool_dir / f"{address}.json"
    return fallback

# slither
def count_swc_from_slither_json(json_path: Path) -> Dict[str, int]:
    counts = zero_counts()
    data = safe_json_load(json_path)
    if not data:
        return counts

    detectors = []
    if isinstance(data, dict):
        res = data.get("results")
        if isinstance(res, dict) and isinstance(res.get("detectors"), list):
            detectors = res.get("detectors", [])
        elif isinstance(data.get("issues"), list):
            detectors = data.get("issues", [])
        elif isinstance(res, list):
            detectors = res
        elif isinstance(data.get("detectors"), list):
            detectors = data.get("detectors", [])
    elif isinstance(data, list):
        detectors = data

    if not isinstance(detectors, list):
        detectors = []

    for item in detectors:
        if isinstance(item, dict):
            det = item.get("check") or item.get("id") or item.get("name")
        elif isinstance(item, str):
            det = item
        else:
            det = None

        if not isinstance(det, str):
            continue

        det = det.strip()
        if not det:
            continue

        swc = SLITHER_TO_SWC.get(det)  # direct lookup only
        if swc is None:
            continue

        key = f"SWC-{int(swc)}"
        if key in counts:
            counts[key] += 1

    return counts

# Mythril parsing
def count_swc_from_mythril_json(json_path: Path) -> Dict[str, int]:
    counts = zero_counts()
    data = safe_json_load(json_path)
    if not data:
        return counts

    issues = data.get("issues") or data.get("results") or []
    if not isinstance(issues, list):
        return counts

    for iss in issues:
        if not isinstance(iss, dict):
            continue

        swc_val = (
            iss.get("swc-id")
            or iss.get("swcID")
            or iss.get("swc_id")
            or iss.get("swcId")
            or iss.get("swc")
        )

        swc_num = -1
        if isinstance(swc_val, int):
            swc_num = swc_val
        elif isinstance(swc_val, str):
            s = swc_val.strip().upper()
            if s.startswith("SWC-"):
                s = s[4:]
            # keep only leading digits
            digits = []
            for ch in s:
                if ch.isdigit():
                    digits.append(ch)
                else:
                    break
            if digits:
                try:
                    swc_num = int("".join(digits))
                except ValueError:
                    swc_num = -1

        # fallback to title or description if not found
        if swc_num == -1:
            title = iss.get("title") or iss.get("description") or ""
            if isinstance(title, str):
                # look for either SWC-### or a number at start
                up = title.upper()
                idx = up.find("SWC-")
                num = -1
                if idx >= 0:
                    buf = []
                    for ch in up[idx+4:idx+8]:
                        if ch.isdigit():
                            buf.append(ch)
                        else:
                            break
                    if buf:
                        try:
                            num = int("".join(buf))
                        except ValueError:
                            num = -1
                else:
                    # try leading number
                    buf = []
                    for ch in up:
                        if ch.isdigit():
                            buf.append(ch)
                        else:
                            break
                    if buf:
                        try:
                            num = int("".join(buf))
                        except ValueError:
                            num = -1
                swc_num = num

        if 100 <= swc_num <= 999:
            key = f"SWC-{swc_num}"
            if key in counts:
                counts[key] += 1

    return counts

def read_summary_csv(path: Path) -> List[dict]:
    rows: List[dict] = []
    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)
    return rows

def write_output_csv(path: Path, rows: List[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

def build_slither_summary() -> List[dict]:
    if not SLITHER_SUMMARY_IN.exists():
        print(Fore.RED + f"[!] Missing {SLITHER_SUMMARY_IN}")
        return []
    print(Fore.CYAN + "[*] Building Slither SWC summary...")

    input_rows = read_summary_csv(SLITHER_SUMMARY_IN)
    output_rows: List[dict] = []

    for r in input_rows:
        address = r.get("address", "")
        status = (r.get("status") or "").strip().lower()  # ok / partial / fail
        solc_version = r.get("solc_version", "")
        elapsed = r.get("elapsed_sec", "")
        json_path_value = r.get("json_path", "")

        row = {"address": address, **zero_counts(), "solc_version": solc_version, "status": status, "elapsed_sec": ""}

        if status in {"ok", "partial"}:
            if elapsed is not None:
                row["elapsed_sec"] = elapsed
            jp = find_json_path(SLITHER_DIR, address, json_path_value)
            counts = count_swc_from_slither_json(jp)
            for k in SWC_COLS:
                row[k] = counts.get(k, 0)
        output_rows.append(row)

    print(Fore.GREEN + f"[✓] Processed {len(output_rows)} Slither rows")
    return output_rows

def build_mythril_summary() -> List[dict]:
    if not MYTHRIL_SUMMARY_IN.exists():
        print(Fore.RED + f"[!] Missing {MYTHRIL_SUMMARY_IN}")
        return []
    print(Fore.CYAN + "[*] Building Mythril SWC summary...")

    input_rows = read_summary_csv(MYTHRIL_SUMMARY_IN)
    output_rows: List[dict] = []

    for r in input_rows:
        address = r.get("address", "")
        status = (r.get("status") or "").strip().lower()  # ok / partial / fail
        solc_version = r.get("solc_version", "")
        elapsed = r.get("elapsed_sec", "")
        json_path_value = r.get("json_path", "")

        row = {"address": address, **zero_counts(), "solc_version": solc_version, "status": status, "elapsed_sec": ""}

        if status in {"ok", "partial"}:
            if elapsed is not None:
                row["elapsed_sec"] = elapsed
            jp = find_json_path(MYTHRIL_DIR, address, json_path_value)
            counts = count_swc_from_mythril_json(jp)
            for k in SWC_COLS:
                row[k] = counts.get(k, 0)
        output_rows.append(row)

    print(Fore.GREEN + f"[✓] Processed {len(output_rows)} Mythril rows")
    return output_rows

def build_overlap_summary() -> list:
    rows = []

    def load_map(path: Path) -> dict:
        data = {}
        if not path.exists():
            return data
        import csv
        with path.open("r", encoding="utf-8") as f:
            r = csv.DictReader(f)
            for line in r:
                addr = line.get("address", "").strip()
                if not addr:
                    continue
                st = (line.get("status") or "").strip().lower()
                counts = {col: int(line.get(col, 0) or 0) for col in SWC_COLS}
                data[addr] = {"status": st, "counts": counts}
        return data

    sl_map = load_map(SLITHER_SUMMARY_OUT)
    my_map = load_map(MYTHRIL_SUMMARY_OUT)

    addresses = sorted(set(sl_map.keys()) | set(my_map.keys()))

    for addr in addresses:
        sl = sl_map.get(addr, {"status": "fail", "counts": {c: 0 for c in SWC_COLS}})
        my = my_map.get(addr, {"status": "fail", "counts": {c: 0 for c in SWC_COLS}})

        sl_fail = sl["status"] == "fail"
        my_fail = my["status"] == "fail"

        if sl_fail and my_fail:
            status = "both fail"
        elif sl_fail:
            status = "slither fail"
        elif my_fail:
            status = "mythril fail"
        else:
            status = "ok"

        row = {"address": addr, **{c: min(sl["counts"].get(c, 0), my["counts"].get(c, 0)) for c in SWC_COLS}, "status": status}
        rows.append(row)

    return rows


def main():
    sl_rows = build_slither_summary()
    my_rows = build_mythril_summary()

    if sl_rows:
        write_output_csv(SLITHER_SUMMARY_OUT, sl_rows)
        print(Fore.YELLOW + f"[→] Wrote {SLITHER_SUMMARY_OUT}")
    if my_rows:
        write_output_csv(MYTHRIL_SUMMARY_OUT, my_rows)
        print(Fore.YELLOW + f"[→] Wrote {MYTHRIL_SUMMARY_OUT}")

    overlap_rows = build_overlap_summary()
    if overlap_rows:
        write_output_csv(OVERLAP_SUMMARY_OUT, overlap_rows)
        print(Fore.YELLOW + f"[→] Wrote {OVERLAP_SUMMARY_OUT}")

if __name__ == "__main__":
    main()
