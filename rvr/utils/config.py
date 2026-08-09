"""
RVR — Config loader
Reads rvr/config/config.yaml (or a path given via --config / RVR_CONFIG) and
exposes it as a single RVRConfig object. Previously config.yaml existed but
nothing in the codebase actually read it — profiles, wordlists, and tool
binary names were all hardcoded instead. This module is the fix: it merges
whatever the YAML file provides on top of built-in defaults, so RVR keeps
working even if the file is missing, partially filled out, or malformed.
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional
from functools import lru_cache

from rvr.utils.console import log_warn

try:
    import yaml
    YAML_OK = True
except ImportError:
    YAML_OK = False


DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "config.yaml"

# Built-in fallback — used for any key missing from config.yaml, and for
# the whole config if the file can't be read at all. Keeps RVR functional
# out of the box even with no config.yaml present.
DEFAULTS: Dict[str, Any] = {
    "wordlists": {
        "web_common": "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "web_medium": "/usr/share/seclists/Discovery/Web-Content/big.txt",
        "dns_common": "/usr/share/seclists/Discovery/DNS/combined_subdomains.txt",
    },
    "tools": {
        "nmap": "nmap",
        "ffuf": "ffuf",
        "gobuster": "gobuster",
        "subfinder": "subfinder",
        "nuclei": "nuclei",
        "enum4linux": "enum4linux-ng",
        "netexec": "netexec",
        "masscan": "masscan",
        "snmpwalk": "snmpwalk",
        "whatweb": "whatweb",
        "showmount": "showmount",
        "rpcinfo": "rpcinfo",
        "theharvester": "theHarvester",
        "gowitness": "gowitness",
        "ldapsearch": "ldapsearch",
    },
    "concurrency": {
        "max_workers": 4,
        "heavy_tools": 2,
    },
    "profiles": {
        "stealth": {
            "nmap_timing": "1",
            "nmap_flags": "-sS --scan-delay 2s",
            "ffuf_rate": 10,
        },
        "normal": {
            "nmap_timing": "3",
            "nmap_flags": "-sS -sV -sC",
            "ffuf_rate": 100,
        },
        "aggressive": {
            "nmap_timing": "4",
            "nmap_flags": "-sS -sV -sC -A",
            "ffuf_rate": 500,
        },
    },
    "output": {
        "base_dir": "~/rvr_loot",
        "pdf_theme": "professional",
    },
}


class RVRConfig:
    def __init__(self, data: Dict[str, Any]):
        self._data = data
        self.wordlists = data.get("wordlists", DEFAULTS["wordlists"])
        self.tools = data.get("tools", DEFAULTS["tools"])
        self.concurrency = data.get("concurrency", DEFAULTS["concurrency"])
        self.profiles = data.get("profiles", DEFAULTS["profiles"])
        self.output = data.get("output", DEFAULTS["output"])

    def tool(self, key: str) -> str:
        """Resolve a logical tool name (e.g. 'enum4linux') to the actual
        binary to invoke. Falls back to the key itself if not configured,
        so an unrecognised key still does something sane rather than
        raising."""
        return self.tools.get(key, key)

    def wordlist(self, key: str) -> Optional[str]:
        return self.wordlists.get(key)

    def base_output_dir(self) -> Path:
        return Path(os.path.expanduser(self.output.get("base_dir", "~/rvr_loot")))


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Merge override onto base, one level deep per top-level section —
    enough for config.yaml's shape (a flat dict of dicts). A partial
    config.yaml (e.g. only overriding 'tools') still gets full defaults
    for every other section."""
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = {**merged[key], **value}
        else:
            merged[key] = value
    return merged


def _resolve_config_path(explicit: Optional[str] = None) -> Path:
    if explicit:
        return Path(explicit).expanduser()
    env_path = os.getenv("RVR_CONFIG")
    if env_path:
        return Path(env_path).expanduser()
    return DEFAULT_CONFIG_PATH


@lru_cache(maxsize=None)
def _load_cached(path_str: str) -> RVRConfig:
    path = Path(path_str)

    if not YAML_OK:
        log_warn("PyYAML not installed — using built-in default configuration")
        return RVRConfig(dict(DEFAULTS))

    if not path.exists():
        if path != DEFAULT_CONFIG_PATH:
            log_warn(f"Config file not found: {path} — using built-in defaults")
        return RVRConfig(dict(DEFAULTS))

    try:
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
        return RVRConfig(_deep_merge(DEFAULTS, raw))
    except Exception as e:
        log_warn(f"Failed to parse config file {path}: {e} — using built-in defaults")
        return RVRConfig(dict(DEFAULTS))


def get_config(explicit_path: Optional[str] = None) -> RVRConfig:
    """Load (and cache) the RVR configuration. Call with an explicit path
    once at startup (e.g. from --config) to pin it for the rest of the
    process; subsequent calls with no argument reuse whatever was loaded
    first."""
    path = _resolve_config_path(explicit_path)
    return _load_cached(str(path))