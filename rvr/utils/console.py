"""
RVR — Console utilities v4
Hacker aesthetic banner with block font, plus thread-safe logging and
richer panels for startup / phase-3 explanation / end-of-scan summary.
"""

import threading
from typing import Optional, List, TYPE_CHECKING

from rich.console import Console
from rich.text import Text
from rich.rule import Rule
from rich.panel import Panel
from rich.table import Table
from rich.box import ROUNDED, SIMPLE
from contextlib import contextmanager
from datetime import datetime

if TYPE_CHECKING:
    from rvr.utils.state import RVRState
    from rvr.modules.registry import ModuleSpec

console = Console()

# Guards every log_* call and the panel renderers below so concurrent
# modules (Phase 3 runs several in a ThreadPoolExecutor) can't interleave
# mid-line and corrupt terminal output. Rich's Console is fine with plain
# console.print() calls happening from other threads while a Progress/Live
# is active on the same console — this lock only protects our own
# multi-part renders (log_section's blank-line + rule + blank-line, etc.)
# from splitting across threads.
_console_lock = threading.Lock()

BANNER = """\
\033[38;5;69m
                                ██████╗ ██╗   ██╗██████╗ 
                                ██╔══██╗██║   ██║██╔══██╗
                                ██████╔╝██║   ██║██████╔╝
                                ██╔══██╗╚██╗ ██╔╝██╔══██╗
                                ██║  ██║ ╚████╔╝ ██║  ██║
                                ╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝\033[0m"""

TAGLINE = "  \033[38;5;60m[ RYXVOID RECON FRAMEWORK ]  ·  v1.0.0  ·  by ryx13  ·  automated pentesting intelligence\033[0m"

DIVIDER = "\033[38;5;237m" + "─" * 60 + "\033[0m"

PROFILE_DESCRIPTIONS = {
    "stealth": "Slow & quiet — T1 timing, 2s scan delay, 10 req/s fuzzing. Use where noise/IDS detection matters.",
    "normal": "Balanced default — T3 timing, standard -sV -sC service detection, 100 req/s fuzzing.",
    "aggressive": "Fast & loud — T4 timing, adds -A (OS detection, traceroute), 500 req/s fuzzing. Best for CTF/lab boxes.",
}


def print_banner():
    print(BANNER)
    print(TAGLINE)
    print()


def log_info(msg: str):
    with _console_lock:
        console.print(f"  [cyan]→[/cyan] {msg}")


def log_success(msg: str):
    with _console_lock:
        console.print(f"  [green]✓[/green] {msg}")


def log_warn(msg: str):
    with _console_lock:
        console.print(f"  [yellow]⚠[/yellow] {msg}")


def log_error(msg: str):
    with _console_lock:
        console.print(f"  [red]✗[/red] {msg}")


def log_section(title: str):
    with _console_lock:
        console.print()
        console.rule(f"[bold cyan]{title}[/bold cyan]", style="dim blue")
        console.print()


def startup_panel(
    target: str,
    target_type: str,
    profile: str,
    output_dir,
    attacker_ip: Optional[str],
    attacker_iface: Optional[str],
    resume: bool = False,
    threads: int = 4,
):
    """Replaces the old plain [*] Target / [*] Profile print lines with a
    single bordered panel that also explains what the chosen profile
    actually does, rather than just naming it."""
    profile_desc = PROFILE_DESCRIPTIONS.get(profile, "")

    body = Table.grid(padding=(0, 2))
    body.add_column(style="bold cyan", justify="right")
    body.add_column()

    body.add_row("Target", f"[bold white]{target}[/bold white] [dim]({target_type})[/dim]")
    body.add_row("Profile", f"[bold white]{profile}[/bold white]")
    body.add_row("", f"[dim]{profile_desc}[/dim]")
    body.add_row("Output", f"[white]{output_dir}[/white]")
    body.add_row("Threads", f"[white]{threads}[/white] concurrent module(s) in Phase 3")

    if attacker_ip:
        body.add_row("Attacker IP", f"[bold white]{attacker_ip}[/bold white] [dim]({attacker_iface})[/dim]")
    else:
        body.add_row("Attacker IP", "[yellow]not detected — connect your VPN before scanning[/yellow]")

    if resume:
        body.add_row("Mode", "[bold yellow]RESUME[/bold yellow] [dim]— skipping modules already completed[/dim]")

    with _console_lock:
        console.print(Panel(
            body,
            title="[bold]Scan Plan[/bold]",
            border_style="blue",
            box=ROUNDED,
            padding=(1, 2),
        ))
        console.print()


def triggered_modules_table(specs: List["ModuleSpec"]):
    """Explanatory table shown before Phase 3 starts — not just *which*
    modules triggered, but *why* (which registry trigger condition matched),
    so the output reads as a decision rather than a black box."""
    table = Table(box=SIMPLE, show_edge=False, pad_edge=False)
    table.add_column("Module", style="bold cyan")
    table.add_column("Triggered because", style="dim")

    for spec in specs:
        table.add_row(spec.name, spec.description or "—")

    with _console_lock:
        console.print(table)
        console.print()


def end_summary_panel(state: "RVRState", elapsed_seconds: int):
    """Replaces the old three plain green print lines at the end of a scan
    with a single panel summarising what was actually found, not just that
    the scan finished."""
    mins, secs = divmod(elapsed_seconds, 60)
    elapsed_str = f"{mins}m {secs}s" if mins else f"{secs}s"

    rows = [
        ("Open ports", str(len(state.open_ports))),
        ("Web findings", str(len(state.web_findings))),
        ("Vulnerabilities (Nuclei)", str(len(state.nuclei_findings))),
    ]
    if state.ftp_findings.get("anonymous_login"):
        rows.append(("FTP", "[red]anonymous login allowed[/red]"))
    if state.database_findings:
        flagged = sum(1 for f in state.database_findings.values()
                      if f.get("empty_password") or f.get("unauthenticated"))
        if flagged:
            rows.append(("Databases", f"[red]{flagged} misconfigured[/red]"))
    if state.ldap_findings.get("anonymous_bind"):
        rows.append(("LDAP", "[red]anonymous bind allowed[/red]"))
    if state.rdp_findings.get("nla_enabled") is False:
        rows.append(("RDP", "[yellow]NLA not enforced[/yellow]"))
    if state.nfs_mounts:
        rows.append(("NFS mounts exposed", str(len(state.nfs_mounts))))
    if state.ai_risk_level:
        risk_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "green"}.get(
            state.ai_risk_level.lower(), "white"
        )
        rows.append(("AI risk assessment", f"[bold {risk_color}]{state.ai_risk_level}[/bold {risk_color}]"))
    if state.failed_modules:
        rows.append(("Failed modules", f"[yellow]{', '.join(state.failed_modules)}[/yellow]"))

    body = Table.grid(padding=(0, 2))
    body.add_column(style="bold", justify="right")
    body.add_column()
    for label, value in rows:
        body.add_row(label, value)

    body.add_row("", "")
    body.add_row("Raw data", f"[dim]{state.output_dir / 'raw_data.json'}[/dim]")
    body.add_row("Report", f"[dim]{state.output_dir / 'report.pdf'}[/dim]")

    with _console_lock:
        console.print(Panel(
            body,
            title=f"[bold green]Scan Complete[/bold green] [dim]— {elapsed_str}[/dim]",
            border_style="green",
            box=ROUNDED,
            padding=(1, 2),
        ))