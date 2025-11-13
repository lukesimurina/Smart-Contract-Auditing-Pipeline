import os, json, requests
from typing import Dict, Any, List, Optional

class EtherscanError(RuntimeError):
    pass

def _api_base() -> str:
    return os.getenv("ETHERSCAN_BASE_URL", "https://api.etherscan.io/v2/api?chainid=1")

def _api_key() -> str:
    k = os.getenv("ETHERSCAN_API_KEY")
    if not k:
        raise EtherscanError("ETHERSCAN_API_KEY not set (put it in your environment or .env)")
    return k

def _get(url: str, params: Dict[str, str]) -> Dict[str, Any]:
    r = requests.get(url, params=params, timeout=30)
    r.raise_for_status()
    return r.json()

#JSON parsing helpers

def _strip_outer_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and ((s[0] == s[-1] == '"') or (s[0] == s[-1] == "'")):
        return s[1:-1]
    return s

def _strip_duplicate_braces(s: str) -> str:
    s = s.strip()
    while s.startswith("{{") and s.endswith("}}"):
        s = s[1:-1].strip()
    return s

def try_parse_any_json(s: str) -> Optional[Any]:
    cand = _strip_duplicate_braces(s)

    # attempt direct parse if it looks like JSON
    if (cand.startswith("{") and cand.endswith("}")) or (cand.startswith("[") and cand.endswith("]")):
        try:
            return json.loads(cand)
        except Exception:
            pass

    # strip quotes then parse
    s1 = _strip_outer_quotes(cand)
    if s1 != cand:
        try:
            return json.loads(s1)
        except Exception:
            pass

    for base in (cand, s1):
        try:
            mid = json.loads(base)
            if isinstance(mid, str):
                return json.loads(_strip_duplicate_braces(_strip_outer_quotes(mid)))
            if isinstance(mid, (dict, list)):
                return mid
        except Exception:
            pass

    return None

def extract_sources_map(obj: Any) -> Optional[Dict[str, str]]:
    if not isinstance(obj, dict):
        return None
    sources = obj.get("sources")
    if not isinstance(sources, dict):
        return None
    out: Dict[str, str] = {}
    for p, meta in sources.items():
        if isinstance(meta, dict) and "content" in meta:
            out[p] = meta["content"]
    return out or None

# public API

def get_source_v1(address: str) -> Dict[str, Any]:
    url = f"{_api_base()}"
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": _api_key(),
    }
    data = _get(url, params)

    if data.get("status") == "0":
        raise EtherscanError(data.get("result") or "Etherscan error")

    result = data.get("result") or []
    if not result:
        raise EtherscanError("Empty result from Etherscan")

    rec = result[0]
    contract_name    = rec.get("ContractName") or "Contract"
    compiler_version = rec.get("CompilerVersion") or ""
    source_code      = rec.get("SourceCode") or ""

    parsed = try_parse_any_json(source_code)
    multi_map = extract_sources_map(parsed) if parsed is not None else None

    remappings = []
    if isinstance(parsed, dict):
        settings = parsed.get("settings")
        if isinstance(settings, dict):
            rms = settings.get("remappings")
            if isinstance(rms, list):
                remappings = [r for r in rms if isinstance(r, str)]

    out: Dict[str, Any] = {
        "address": address.lower(),
        "contract_name": contract_name,
        "compiler_version": compiler_version,
        "remappings": remappings,
    }

    if multi_map:
        out["files"] = [{"path": p, "content": c} for p, c in multi_map.items()]
    else:
        fname = (contract_name if contract_name else "Contract").strip()
        if not fname.endswith(".sol"):
            fname += ".sol"
        out["single"] = {"fileName": fname, "content": source_code}

    return out

def choose_entry_file(files: List[Dict[str, str]], contract_name: str) -> str:
    needle = f"contract {contract_name}"
    for f in files:
        try:
            if needle in f.get("content", ""):
                return f["path"]
        except Exception:
            pass
    for f in files:
        if f.get("path","").startswith("contracts/"):
            return f["path"]
    return files[0]["path"] if files else "Contract.sol"