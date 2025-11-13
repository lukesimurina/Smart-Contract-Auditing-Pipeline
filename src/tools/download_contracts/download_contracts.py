import os, sys, csv, json
from pathlib import Path
from typing import Dict, Any
from dotenv import load_dotenv
from decimal import Decimal
from typing import Optional
from tqdm import tqdm
from colorama import init, Fore, Style
sys.path.append(str(Path(__file__).resolve().parent.parent))
from paths import ensure_dirs, src_root, safe_dest
from etherscan_client import get_source_v1, choose_entry_file, EtherscanError

# initialize colorama
init(autoreset=True)

def write_metadata(base_dir: Path, meta: Dict[str, Any], entry_rel: str):
    payload = {
        "address": meta["address"],
        "contract_name": meta.get("contract_name"),
        "compiler_version": meta.get("compiler_version"),
        "entry": f"src/{entry_rel}",
    }
    # persist remappings if the client provided them
    if meta.get("remappings"):
        payload["remappings"] = list(meta["remappings"])

    (base_dir / "metadata.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8"
    )
    (base_dir / "main.solpath").write_text(f"src/{entry_rel}\n", encoding="utf-8")


def save_sources(address: str, payload: Dict[str, Any], chain: str = "mainnet") -> None:
    root = src_root(address, chain)
    base = root.parent

    if "files" in payload and payload["files"]:
        entry = choose_entry_file(payload["files"], payload.get("contract_name") or "")
        for f in payload["files"]:
            dest = safe_dest(root, f["path"])
            dest.write_text(f["content"], encoding="utf-8")
        entry_rel = Path(entry).as_posix().lstrip("/")
        write_metadata(base, payload, entry_rel)
        tqdm.write(Fore.GREEN + f"[✓] wrote multi-file sources for {address}")
        return

    #single-file branch
    single = payload["single"]
    content = single["content"]

    from etherscan_client import try_parse_any_json, extract_sources_map
    parsed = try_parse_any_json(content)
    mm = extract_sources_map(parsed) if parsed is not None else None

    if mm:
        files = [{"path": p, "content": c} for p, c in mm.items()]
        entry = choose_entry_file(files, payload.get("contract_name") or "")
        for f in files:
            dest = safe_dest(root, f["path"])
            dest.write_text(f["content"], encoding="utf-8")
        entry_rel = Path(entry).as_posix().lstrip("/")
        write_metadata(base, payload, entry_rel)
        tqdm.write(Fore.GREEN + f"[✓] wrote multi-file sources for {address} (recovered from JSON-in-single)")
        return

    # truly single-file
    dest = safe_dest(root, single["fileName"])
    dest.write_text(content, encoding="utf-8")
    write_metadata(base, payload, Path(single["fileName"]).as_posix())
    tqdm.write(Fore.GREEN + f"[✓] wrote single-file source for {address}")

def main():
    import argparse, re, time
    ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")

    parser = argparse.ArgumentParser(description="Download verified contracts from Etherscan")
    parser.add_argument("--csv", help="Path to CSV file with addresses in column B (or any column; we use B)", default=None)
    parser.add_argument("address", nargs="?", help="Single contract address (0x...)")
    args = parser.parse_args()

    load_dotenv()
    ensure_dirs()

    # CSV mode
    if args.csv:
        csv_path = Path(args.csv)
        if not csv_path.exists():
            print(Fore.RED + f"[!] CSV not found: {csv_path}")
            sys.exit(1)

        addrs: list[str] = []
        with open(csv_path, newline="") as f:
            r = csv.reader(f)
            for row in r:
                if len(row) < 2:
                    continue
                cell = (row[1] or "").strip()  # column B
                if ADDR_RE.fullmatch(cell):
                    addrs.append(cell.lower())

        if not addrs:
            print(Fore.YELLOW + "[i] No valid addresses found in column B.")
            return

        ok = 0
        fail = 0
        with tqdm(total=len(addrs), desc="Downloading", unit="ct", dynamic_ncols=True) as pbar:
            for addr in addrs:
                pbar.set_postfix(ok=ok, fail=fail, addr=addr[:10] + "…")
                try:
                    payload = get_source_v1(addr)
                    save_sources(addr, payload)
                    tqdm.write(Fore.GREEN + f"[✓] saved sources for {addr}")
                    ok += 1
                except EtherscanError as e:
                    tqdm.write(Fore.RED + f"[!] {addr}: {e}")
                    fail += 1
                except Exception as e:
                    tqdm.write(Fore.RED + f"[!] {addr}: unexpected error: {e}")
                    fail += 1
                finally:
                    pbar.set_postfix(ok=ok, fail=fail, addr=addr[:10] + "…")
                    pbar.update(1)
                    time.sleep(0.25)  # throttle for free API keys

        tqdm.write(Fore.GREEN + f"Done. Success: {ok}  " + Fore.RED + f"Failed: {fail}")
        return

    if not args.address:
        print("Usage:\n  python scripts/download_contracts.py 0xYourAddress\n"
              "  python scripts/download_contracts.py --csv path/to/file.csv")
        sys.exit(1)


if __name__ == "__main__":
    main()
