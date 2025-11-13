import sys, subprocess, json
from pathlib import Path
from shutil import copy2
sys.path.append(str(Path(__file__).resolve().parent.parent))
from paths import flat_out, src_root
from colorama import init, Fore, Style
from tqdm import tqdm

# initialize colorama
init(autoreset=True)



def read_entry_path(address: str, chain: str = "mainnet") -> Path:
    base = src_root(address, chain).parent
    main_path = (base / "main.solpath").read_text(encoding="utf-8").strip()
    entry_path = (base / main_path).resolve()
    if not entry_path.exists():
        raise FileNotFoundError(f"Entry file not found: {entry_path}")
    return entry_path


def forge_flatten(entry_path: Path, out_path: Path, base_dir: Path, remappings: list[str]):
    base_dir = base_dir.resolve()
    entry_rel = entry_path.relative_to(base_dir)

    cmd = [
        "forge", "flatten", str(entry_rel),
        "--root", "./src/" 
    ]
    for r in remappings:
        cmd += ["--remappings", r]

    tqdm.write(f"[+] Flattening {entry_path} -> {out_path}")
    res = subprocess.run(cmd, cwd=base_dir, text=True, capture_output=True)
    if res.returncode != 0 or not res.stdout.strip():
        raise RuntimeError(f"Forge flatten failed:\n{res.stderr or res.stdout}")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(res.stdout, encoding="utf-8")
    tqdm.write(Fore.GREEN + f"[✓] Wrote {out_path}")


def main():
    chain = (sys.argv[1] if len(sys.argv) > 1 else "mainnet").strip().lower()
    base = Path("data/raw") / chain
    targets = sorted(base.glob("*/main.solpath"))
    if not targets:
        tqdm.write(Fore.YELLOW + f"[!] No contracts found in {base}")
        return

    total = len(targets)
    tqdm.write(f"{Fore.YELLOW}[+] Found {total} contracts with main.solpath{Style.RESET_ALL}")

    ok = 0
    fail = 0

    with tqdm(total=total, desc="Flattening", unit="ct", dynamic_ncols=True) as pbar:
        for mainpath in targets:
            address = mainpath.parent.name.lower()
            pbar.set_postfix(addr=address[:10] + "…", ok=ok, fail=fail)

            try:
                entry_path = read_entry_path(address, chain)
                base_dir = mainpath.parent
                meta_path = base_dir / "metadata.json"

                remappings = []
                if meta_path.exists():
                    try:
                        meta = json.loads(meta_path.read_text(encoding="utf-8"))
                        remappings = meta.get("remappings", []) or []
                    except Exception as e:
                        tqdm.write(f"{Fore.YELLOW}[i] Could not parse remappings for {address}: {e}{Style.RESET_ALL}")

                out_path = flat_out(address, chain)
                forge_flatten(entry_path, out_path, base_dir, remappings)

                if meta_path.exists():
                    copy2(meta_path, out_path.parent / "metadata.json")
                else:
                    tqdm.write(f"{Fore.YELLOW}[i] No metadata.json found for {address}; skipping copy{Style.RESET_ALL}")

                ok += 1
            except KeyboardInterrupt:
                tqdm.write(f"{Fore.RED}[!] Interrupted by user — partial results saved.{Style.RESET_ALL}")
                break
            except Exception as e:
                fail += 1
                tqdm.write(f"{Fore.RED}[!] Flatten failed for {address}: {e}{Style.RESET_ALL}")
            finally:
                pbar.set_postfix(addr=address[:10] + "…", ok=ok, fail=fail)
                pbar.update(1)

    tqdm.write(f"{Fore.GREEN}Done. Success: {ok}  {Fore.RED}Failed: {fail}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
