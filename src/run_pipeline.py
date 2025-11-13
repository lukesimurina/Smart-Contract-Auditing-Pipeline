import subprocess
import argparse
from pathlib import Path
import sys
import os

ROOT = Path(__file__).resolve().parent
ENVS = ROOT.parent / "envs"

def run_in_env(env_dir: Path, script: Path, args=(), cwd=None, extra_env=None):
    bin_dir = env_dir / ("Scripts" if os.name == "nt" else "bin")
    py = bin_dir / ("python.exe" if os.name == "nt" else "python")

    env = os.environ.copy()
    env.pop("PYTHONHOME", None)
    env.pop("PYTHONPATH", None)
    env["VIRTUAL_ENV"] = str(env_dir)
    
    parts = [str(bin_dir)]
    usr_local_bin = Path.home() / ".local" / "bin"
    if usr_local_bin.exists():
        parts.append(str(usr_local_bin))
    solc_current = Path.home() / ".solc-select" / "current"
    if (solc_current / ("solc.exe" if os.name == "nt" else "solc")).exists():
        parts.append(str(solc_current))
    env["PATH"] = os.pathsep.join(parts + [env.get("PATH", "")])

    if extra_env:
        env.update(extra_env)

    # Run
    cmd = [str(py), str(script), *map(str, args)]
    subprocess.run(cmd, check=True, cwd=str(cwd) if cwd else None, env=env)

def main():
    parser = argparse.ArgumentParser(description="Smart Contract Analysis Pipeline")
    parser.add_argument("--csv", type=str, required=True,
                        help="Path to CSV file containing contract addresses (Downloaded Etherscan CSV)")
    parser.add_argument("--download", action="store_true", help="Run download stage only")
    parser.add_argument("--flatten", action="store_true", help="Run flattening stage only")
    parser.add_argument("--slither", action="store_true", help="Run Slither analysis only")
    parser.add_argument("--mythril", action="store_true", help="Run Mythril analysis only")
    parser.add_argument("--analyse_results", action="store_true", help="Aggregate results after analysis")
    parser.add_argument("--all", action="store_true", help="Run all pipeline stages sequentially")
    args = parser.parse_args()

    if args.all or args.download:
        print("[+] Downloading verified contracts from Etherscan…")
        run_in_env(ENVS / ".venv", 
                   ROOT / "tools" / "download_contracts" / "download_contracts.py", 
                   ["--csv", str(args.csv)])

    if args.all or args.flatten:
        print("[+] Flattening contracts with Foundry Forge…")
        run_in_env(ENVS / ".venv", 
                   ROOT / "tools" / "flatten_contracts" / "flatten_contracts.py")

    if args.all or args.slither:
        print("[+] Running Slither on all flattened contracts…")
        run_in_env(ENVS / ".venv-slither", 
                   ROOT / "tools" / "slither_analyse" / "run_slither_analyse.py")

    if args.all or args.mythril:
        print("[+] Running Mythril on all flattened contracts…")
        run_in_env(ENVS / ".venv-mythril", 
                   ROOT / "tools" / "mythril_analyse" / "run_mythril_analyse.py", 
                   ["--timeout", str("180"), "--solver-timeout", str("20"), "--depth", str("15")])

    if args.all or args.analyse_results:
        print("[+] Analyzing and aggregating results from Slither and Mythril…")
        run_in_env(ENVS / ".venv", 
                   ROOT / "tools" / "analyse_results" / "generate_summaries.py")

if __name__ == "__main__":
    main()