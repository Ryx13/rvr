"""
RVR — CLI entry point (v2)
Argument parsing, environment validation and orchestration bootstrap for the
full pipeline and micro-variant modes. Installed as the `rvr` command via
pyproject.toml's [project.scripts]; main.py remains as a thin shim for the
global launcher and direct invocations.
"""

import argparse
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

# Make the package importable when invoked as `python main.py` or from an
# uninstalled checkout (the global launcher relies on this).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rvr.utils.console import VERSION, console, print_banner, startup_panel, log_info
from rvr.utils.state import RVRState
from rvr.utils.validator import validate_target
from rvr.utils.network_info import get_attacker_ip
from rvr.utils.config import get_config
from rvr.core import RVRCore

MICRO_TOOLS = [
    "nmap", "ffuf", "subfinder", "nuclei",
    "enum4linux", "netexec", "snmpwalk", "whatweb",
    "ftp", "ldapsearch", "rdp",
    "kerberos", "bloodhound", "searchsploit", "vhosts", "pivot", "spray",
]

SKIP_MODULES = [
    "osint", "network", "web", "smb", "nfs", "snmp", "ftp",
    "databases", "ldap", "rdp", "kerberos", "bloodhound", "adcs",
    "exploits", "ai", "report",
]

# Runtime dependencies that must import cleanly before anything else runs.
# The global launcher performs the same check (and can auto-repair the venv);
# this is the safety net for `python -m rvr.cli` style invocations.
CORE_DEPS = ["rich", "requests", "dotenv", "yaml", "reportlab"]


def check_runtime_deps() -> bool:
    import importlib
    missing = []
    for dep in CORE_DEPS:
        try:
            importlib.import_module(dep)
        except ImportError:
            missing.append(dep)
    if missing:
        console.print(f"[red][!] Missing Python dependencies: {', '.join(missing)}[/red]")
        console.print("[yellow][!] Repair with:[/yellow]")
        console.print("        cd ~/Documents/Projects/rvr && .venv/bin/pip install -r requirements.txt")
        console.print("    (or let the global launcher heal the environment automatically)")
        return False
    return True


class RVRHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Preserves explicit newlines inside an argument's help= text, not just
    the epilog — lets --tool/--skip lay out their choices as a readable
    list instead of being squashed into one auto-wrapped paragraph."""
    def _split_lines(self, text, width):
        return text.splitlines()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rvr",
        description=f"RVR v{VERSION} — Ryxvoid Recon Framework (CPTS / HTB edition)",
        formatter_class=RVRHelpFormatter,
        epilog="""
Examples:
  rvr -t 10.10.11.1                          Full suite, normal profile
  rvr -t 10.10.11.1 --htb                    HTB machine workflow (hostname, /etc/hosts, notes)
  rvr -t 10.10.11.1 --htb --profile aggressive
  rvr -t 10.10.11.1 --creds svc-web:'P@ss'   Credentialed AD collection (Kerberoast/BloodHound/Certipy)
  rvr -t 10.10.11.1 --skip ai exploits     Skip phases by name
  rvr -t example.com --profile normal        Domain target — runs OSINT first
  rvr -t 10.10.11.1 --resume                 Resume a scan, skip completed modules
  rvr -t 10.10.11.1 -o ./loot --threads 8    Custom output dir + thread count
  rvr -t 10.10.11.1 --udp                    Include a UDP top-200 sweep

  Micro-variant mode — run one tool interactively instead of the full pipeline:
  rvr --tool nmap -t 10.10.11.1              Port scan only
  rvr --tool kerberos -t 10.10.11.1          Kerbrute + AS-REP roast (or Kerberoast with creds)
  rvr --tool bloodhound -t 10.10.11.1        BloodHound collection
  rvr --tool searchsploit -t 10.10.11.1      Correlate state's services against Exploit-DB
  rvr --tool vhosts -t 10.10.11.1            vHost fuzzing on the first web port
  rvr --tool pivot -t 10.10.11.1             Ligolo-ng / Chisel pivot command generator
  rvr --tool spray -t 10.10.11.1             Password spray (interactive, lockout warnings)

Authorized targets only. You are responsible for compliance with applicable law.
        """
    )

    parser.add_argument(
        "-t", "--target",
        required=True,
        metavar="TARGET",
        help="Target IP, subnet, or domain (e.g. 10.10.11.1 or example.com)"
    )
    parser.add_argument(
        "--profile",
        choices=["stealth", "normal", "aggressive"],
        default="normal",
        metavar="PROFILE",
        help="Scan profile: stealth | normal | aggressive (default: normal)"
    )
    parser.add_argument(
        "--tool",
        choices=MICRO_TOOLS,
        metavar="TOOL",
        help=(
            "Run a single tool interactively instead of the full pipeline:\n"
            "  nmap          port scan — quick top-1000 / full 1-65535 / UDP / custom flags\n"
            "  ffuf          directory & file fuzzing\n"
            "  nuclei        vulnerability template scan\n"
            "  whatweb       web technology fingerprinting\n"
            "  subfinder     passive subdomain enumeration\n"
            "  enum4linux    SMB enumeration (enum4linux-ng)\n"
            "  netexec       SMB anonymous login / share / RID-cycling checks\n"
            "  snmpwalk      SNMP community walk\n"
            "  ftp           FTP anonymous login check + banner grab\n"
            "  ldapsearch    LDAP anonymous bind check + AD enumeration\n"
            "  rdp           RDP NTLM info leak + NLA/encryption check\n"
            "  kerberos      Kerbrute + AS-REP roast, or Kerberoast (asks for creds)\n"
            "  bloodhound    BloodHound collection (anonymous or --creds)\n"
            "  searchsploit  correlate discovered service versions against Exploit-DB\n"
            "  vhosts        virtual host fuzzing on the first open web port\n"
            "  pivot         Ligolo-ng / Chisel / SSH pivot command generator\n"
            "  spray         password spray via NetExec (interactive, lockout warnings)"
        )
    )
    parser.add_argument(
        "--htb", action="store_true",
        help="HTB / CPTS workflow: discover the machine hostname, add it to\n"
             "/etc/hosts (asks first), and generate a notes.md engagement\n"
             "scratchpad once enumeration finishes"
    )
    parser.add_argument(
        "--creds", metavar="USER:PASS",
        help="AD credentials for credentialed collection — unlocks Kerberoast,\n"
             "credentialed BloodHound and Certipy template enumeration.\n"
             "Opt-in only: no credential attack ever runs without them"
    )
    parser.add_argument(
        "-o", "--output",
        metavar="DIR",
        help="Override output directory (default: <config output.base_dir>/<target>,\n"
             "normally ~/rvr_loot/<target>)"
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        help="Path to a config.yaml to use instead of the bundled default\n"
             "(env var RVR_CONFIG also works)"
    )
    parser.add_argument(
        "--skip",
        nargs="+",
        choices=SKIP_MODULES,
        metavar="MODULE",
        help=(
            "Skip one or more phases/modules (space-separated):\n"
            "  osint       passive OSINT — subfinder/theHarvester (domain targets only)\n"
            "  network     Nmap sweep (everything else depends on it)\n"
            "  web         WhatWeb, ffuf, Nuclei, gowitness, vHost/API/SSL discovery\n"
            "  smb         enum4linux-ng, NetExec\n"
            "  nfs         showmount / rpcinfo enumeration\n"
            "  snmp        snmpwalk\n"
            "  ftp         anonymous login check + banner grab\n"
            "  databases   MySQL / MSSQL / PostgreSQL / Redis / MongoDB checks\n"
            "  ldap        anonymous bind check + AD enumeration\n"
            "  rdp         NTLM info leak + NLA/encryption check\n"
            "  kerberos    Kerbrute / AS-REP roast / Kerberoast (port 88)\n"
            "  bloodhound  BloodHound collection (DC-like targets)\n"
            "  adcs        AD CS web enrollment + certipy checks\n"
            "  exploits    searchsploit Exploit-DB correlation\n"
            "  ai          AI analysis (Gemini / Groq / Claude / OpenAI)\n"
            "  report      PDF + Markdown report generation\n"
            "Example: --skip osint ai"
        )
    )
    parser.add_argument("--no-ai",      action="store_true", help="Disable AI analysis (all providers)")
    parser.add_argument("--no-discord", action="store_true", help="Disable Discord webhook")
    parser.add_argument("--no-report",  action="store_true", help="Skip PDF/Markdown report generation")
    parser.add_argument(
        "--resume", action="store_true",
        help="Resume a previous scan in the output directory — skip modules that\n"
             "already completed successfully instead of re-running them (report\n"
             "generation always re-runs so it reflects current state)"
    )
    parser.add_argument("--ports",      metavar="PORTS",     help="Override port range (e.g. --ports 1-65535)")
    parser.add_argument("--udp", action="store_true", help="Include UDP scan (top 200 ports)")
    parser.add_argument(
        "--threads", type=int, default=None, metavar="N",
        help="Max concurrent threads for Phase 3 (default: config.yaml's\n"
             "concurrency.max_workers, normally 4)"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output — print every underlying command as it runs")
    parser.add_argument("--version",    action="version", version=f"RVR v{VERSION}")

    return parser


def ensure_sudo(state) -> None:
    """Pre-authenticate sudo before any scan phase starts.

    nmap needs raw-socket privileges for -sS, so network.py prepends
    'sudo' to its own nmap invocations when not already running as root.
    The problem: those calls happen inside Rich Live displays (spinners /
    progress bars) that continuously repaint the terminal. sudo's password
    prompt writes straight to /dev/tty, and the live redraw loop overwrites
    it before it's ever visible — the scan just hangs silently until the
    600s subprocess timeout fires, with no indication a password was ever
    needed.

    Authenticating here, before any Live display exists, puts the prompt
    on a clean terminal. A background thread then refreshes the cached
    credential periodically so a long scan can't lose it mid-run and hit
    the exact same hidden-prompt hang deeper inside the pipeline.
    """
    if os.geteuid() == 0:
        return

    # Nothing in this run will need raw sockets — skip the prompt entirely.
    needs_nmap = state.tool == "nmap" or "network" not in state.skip
    if not needs_nmap:
        return

    console.print("[cyan][*] nmap needs raw-socket privileges — checking sudo access...[/cyan]")
    try:
        result = subprocess.run(["sudo", "-v"])
    except FileNotFoundError:
        console.print("[yellow][!] sudo not found — nmap scans requiring raw sockets will fail[/yellow]")
        return

    if result.returncode != 0:
        console.print("[yellow][!] sudo authentication failed — nmap scans will likely fail or hang[/yellow]")
        return

    def _keepalive():
        while True:
            time.sleep(240)
            try:
                subprocess.run(["sudo", "-n", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass

    threading.Thread(target=_keepalive, daemon=True).start()
    console.print()


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Self-healing safety net — if core deps are broken (e.g. a Kali Python
    # upgrade invalidated the venv), say so instead of a raw traceback.
    if not check_runtime_deps():
        sys.exit(1)

    # Load config first — everything below can rely on it. --config (or
    # RVR_CONFIG) overrides the bundled rvr/config/config.yaml; a missing
    # or invalid file falls back to built-in defaults with a warning,
    # rather than crashing startup.
    config = get_config(args.config)

    # Print banner
    print_banner()

    # Validate target
    target_type = validate_target(args.target)
    if not target_type:
        console.print(f"[red][!] Invalid target: {args.target}[/red]")
        sys.exit(1)

    # --creds format check — everything downstream assumes "user:pass"
    if args.creds and ":" not in args.creds:
        console.print("[red][!] --creds expects USER:PASS format (e.g. --creds svc-web:'Summer2024!')[/red]")
        sys.exit(1)

    # Build output directory
    if args.output:
        output_dir = Path(args.output)
    else:
        safe_target = args.target.replace("/", "_").replace(":", "_")
        output_dir = config.base_output_dir() / safe_target

    output_dir.mkdir(parents=True, exist_ok=True)

    # Build skip list
    skip = set(args.skip or [])
    if args.no_ai:
        skip.add("ai")
    if args.no_report:
        skip.add("report")

    threads = args.threads if args.threads is not None else config.concurrency.get("max_workers", 4)

    # Capture attacker IP (tun0 for VPN, fallback to wlan0)
    atk_ip, atk_iface = get_attacker_ip()

    # Initialise state
    state = RVRState(
        target=args.target,
        target_type=target_type,
        profile=args.profile,
        output_dir=output_dir,
        skip=skip,
        verbose=args.verbose,
        threads=threads,
        port_override=args.ports,
        tool=args.tool,
        no_discord=args.no_discord,
        udp_scan=getattr(args, "udp", False),
        attacker_ip=atk_ip,
        attacker_iface=atk_iface,
        resume=args.resume,
        htb_mode=args.htb,
        ad_credentials=args.creds,
    )

    # --resume: hydrate results + completion tracking from a previous scan
    # in this output dir, if one exists. Current-run options (profile,
    # skip, threads, etc.) always come from this invocation's CLI args —
    # only scan results and which modules already succeeded are restored.
    resumed_ok = False
    if args.resume:
        previous = RVRState.load_previous_scan(output_dir)
        if previous:
            state.hydrate_from_dict(previous)
            resumed_ok = True
        else:
            console.print("[yellow][!] --resume set but no previous scan found in this output dir — starting fresh[/yellow]")

    startup_panel(
        target=args.target,
        target_type=target_type,
        profile=args.profile,
        output_dir=output_dir,
        attacker_ip=atk_ip,
        attacker_iface=atk_iface,
        resume=resumed_ok,
        threads=threads,
        htb=args.htb,
        micro=args.tool,
        creds=bool(args.creds),
    )

    if resumed_ok:
        done = ", ".join(state.completed_modules) or "none"
        log_info(f"Already completed: {done}")
        console.print()

    # Authenticate sudo now, on a clean terminal, before any phase's Rich
    # Live display (spinner/progress bar) starts — see ensure_sudo()'s
    # docstring for why this has to happen here and not lazily.
    ensure_sudo(state)

    # Run
    core = RVRCore(state)

    if args.tool:
        core.run_micro(args.tool)
    else:
        core.run_full()


if __name__ == "__main__":
    main()
