#!/usr/bin/env python3
"""
RVR — Ryxvoid Recon Framework
Main entry point and CLI orchestrator
"""

import argparse
import sys
import os
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from rvr.utils.console import console, print_banner
from rvr.utils.state import RVRState
from rvr.utils.validator import validate_target
from rvr.utils.network_info import get_attacker_ip
from rvr.core import RVRCore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rvr",
        description="RVR — Ryxvoid Recon Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  rvr -t 10.10.11.1                          Full suite, normal profile
  rvr -t 10.10.11.1 --profile stealth        Full suite, stealth profile
  rvr -t 10.10.11.1 --profile aggressive     Full suite, aggressive profile
  rvr -t example.com --profile normal        Domain target with OSINT
  rvr --tool nmap -t 10.10.11.1             Micro-variant: nmap only
  rvr --tool ffuf -t 10.10.11.1             Micro-variant: ffuf only
  rvr --tool enum4linux -t 10.10.11.1       Micro-variant: SMB enum only
  rvr -t 10.10.11.1 --resume                Resume a scan, skip completed modules
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
        choices=["nmap", "ffuf", "subfinder", "nuclei",
                 "enum4linux", "netexec", "snmpwalk", "whatweb",
                 "ftp", "ldapsearch", "rdp"],
        metavar="TOOL",
        help="Run a single tool in interactive micro-variant mode"
    )
    parser.add_argument(
        "-o", "--output",
        metavar="DIR",
        help="Override output directory (default: ~/rvr_loot/<target>)"
    )
    parser.add_argument(
        "--skip",
        nargs="+",
        choices=["osint", "network", "web", "smb", "nfs", "snmp",
                 "ftp", "databases", "ldap", "rdp", "ai", "report"],
        metavar="MODULE",
        help="Skip specific modules (e.g. --skip osint ai)"
    )
    parser.add_argument("--no-ai",      action="store_true", help="Disable Gemini AI analysis")
    parser.add_argument("--no-discord", action="store_true", help="Disable Discord webhook")
    parser.add_argument("--no-report",  action="store_true", help="Skip PDF report generation")
    parser.add_argument(
        "--resume", action="store_true",
        help="Resume a previous scan in the output directory — skip modules that "
             "already completed successfully instead of re-running them (report "
             "generation always re-runs so it reflects current state)"
    )
    parser.add_argument("--ports",      metavar="PORTS",     help="Override port range (e.g. --ports 1-65535)")
    parser.add_argument("--udp", action="store_true", help="Include UDP scan (top 200 ports)")
    parser.add_argument("--threads",    type=int, default=4, metavar="N", help="Max concurrent threads (default: 4)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--version",    action="version", version="RVR v1.0.0")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Print banner
    print_banner()

    # Validate target
    target_type = validate_target(args.target)
    if not target_type:
        console.print(f"[red][!] Invalid target: {args.target}[/red]")
        sys.exit(1)

    # Build output directory
    if args.output:
        output_dir = Path(args.output)
    else:
        safe_target = args.target.replace("/", "_").replace(":", "_")
        output_dir = Path.home() / "rvr_loot" / safe_target

    output_dir.mkdir(parents=True, exist_ok=True)

    # Build skip list
    skip = set(args.skip or [])
    if args.no_ai:
        skip.add("ai")
    if args.no_report:
        skip.add("report")

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
        threads=args.threads,
        port_override=args.ports,
        tool=args.tool,
        no_discord=args.no_discord,
        udp_scan=getattr(args, "udp", False),
        attacker_ip=atk_ip,
        attacker_iface=atk_iface,
        resume=args.resume,
    )

    # --resume: hydrate results + completion tracking from a previous scan
    # in this output dir, if one exists. Current-run options (profile,
    # skip, threads, etc.) always come from this invocation's CLI args —
    # only scan results and which modules already succeeded are restored.
    if args.resume:
        previous = RVRState.load_previous_scan(output_dir)
        if previous:
            state.hydrate_from_dict(previous)
            done = ", ".join(state.completed_modules) or "none"
            console.print(f"[cyan][*] Resuming previous scan — already completed: {done}[/cyan]")
        else:
            console.print("[yellow][!] --resume set but no previous scan found in this output dir — starting fresh[/yellow]")

    # Print startup info
    console.print(f"[cyan][*] Target     :[/cyan] [bold]{args.target}[/bold] ({target_type})")
    console.print(f"[cyan][*] Profile    :[/cyan] [bold]{args.profile}[/bold]")
    console.print(f"[cyan][*] Output dir :[/cyan] [bold]{output_dir}[/bold]")

    if atk_ip:
        console.print(f"[cyan][*] Attacker IP :[/cyan] [bold]{atk_ip}[/bold] ({atk_iface})")
    else:
        console.print("[yellow][!] No VPN/network interface detected — connect OpenVPN first[/yellow]")

    console.print(f"[cyan][*] Started    :[/cyan] [bold]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/bold]")
    console.print()

    # Run
    core = RVRCore(state)

    if args.tool:
        core.run_micro(args.tool)
    else:
        core.run_full()


if __name__ == "__main__":
    main()