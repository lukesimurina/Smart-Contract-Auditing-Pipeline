# paths.py
from pathlib import Path

DATA = Path("data")
RAW = DATA / "raw"
FLAT = DATA / "flattened"
RES = DATA / "results"

def ensure_dirs():
    for p in (RAW, FLAT, RES):
        p.mkdir(parents=True, exist_ok=True)

def src_root(address: str, chain: str = "mainnet") -> Path:
    r = RAW / chain / address.lower() / "src"
    r.mkdir(parents=True, exist_ok=True)
    return r

def flat_out(address: str, chain: str = "mainnet") -> Path:
    o = FLAT / chain / address.lower()
    o.mkdir(parents=True, exist_ok=True)
    return o / f"{address.lower()}.sol"

def safe_dest(root: Path, relative: str) -> Path:
    rel = Path(relative.lstrip("/"))              # normalise
    dest = (root / rel).resolve()
    root_res = root.resolve()
    if dest == root_res or root_res in dest.parents:
        dest.parent.mkdir(parents=True, exist_ok=True)
        return dest
    raise ValueError(f"Unsafe path escape blocked: {relative}")
