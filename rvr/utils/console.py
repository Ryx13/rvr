"""
RVR — Console utilities v5
The face of the framework: gradient banner, phase-tracked section headers,
an informative startup panel, and an end-of-scan dashboard that summarises
what was actually found (services, severity-ranked findings, deliverables)
instead of just confirming the scan finished.

Everything renders through Rich so the look adapts to terminal capability,
and every public call is serialised by _console_lock — Phase 3 runs several
modules in a thread pool, and their step-by-step output must never interleave
mid-line.
"""

import threading
from datetime import datetime
from typing import Optional, List, TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.box import ROUNDED, SIMPLE
from rich import box

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

VERSION = "2.0.0"

BANNER_ART = """\
██████╗ ██╗   ██╗██████╗
██╔══██╗██║   ██║██╔══██╗
██████╔╝██║   ██║██████╔╝
██╔══██╗╚██╗ ██╔╝██╔══██╗
██║  ██║ ╚████╔╝ ██║  ██║
╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝"""

# Row-by-row colour ramp for the banner (256-colour indices, blue → magenta)
BANNER_GRADIENT = ["69", "75", "99", "135", "171", "207"]

PROFILE_DESCRIPTIONS = {
    "stealth": "Slow & quiet — T1 timing, 2s scan delay, 10 req/s fuzzing. Use where noise/IDS detection matters.",
    "normal": "Balanced default — T3 timing, standard -sV -sC service detection, 100 req/s fuzzing.",
    "aggressive": "Fast & loud — T4 timing, adds -A (OS detection, traceroute), 500 req/s fuzzing. Best for CTF/lab boxes.",
}

SEV_STYLE = {
    "Critical": "bold red",
    "High": "bold dark_orange",
    "Medium": "bold yellow",
    "Low": "bold green",
    "Informational": "bold blue",
}
SEV_ICON = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🟢",
    "Informational": "🔵",
}

# Phase/section history — appended by log_section, rendered in the end panel
# so the closing dashboard doubles as a "what actually ran" checklist.
_phase_log: List[tuple] = []


def print_banner():
    art = Text()
    for i, line in enumerate(BANNER_ART.splitlines()):
        art.append(f"  {line}\n", style=f"color({BANNER_GRADIENT[i % len(BANNER_GRADIENT)]})")

    tagline = Text.assemble(
        ("  RYXVOID RECON FRAMEWORK", "bold color(81)"),
        (f"  ·  v{VERSION}", "bold color(207)"),
        ("  ·  CPTS / HTB edition\n", "color(245)"),
        ("  recon · web · AD attacks · exploits · AI · reporting\n", "color(60)"),
    )

    with _console_lock:
        console.print()
        console.print(art)
        console.print(tagline)
        console.print()


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
    """Render a phase header and record it in the phase log for the end
    dashboard. Called exactly once per pipeline phase by the orchestrator."""
    _phase_log.append((title, datetime.now()))
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
    htb: bool = False,
    micro: Optional[str] = None,
    creds: bool = False,
):
    """Single bordered panel that explains what this run will actually do —
    the chosen profile's behaviour, special modes, and network position."""
    profile_desc = PROFILE_DESCRIPTIONS.get(profile, "")

    body = Table.grid(padding=(0, 2))
    body.add_column(style="bold cyan", justify="right")
    body.add_column()

    if micro:
        body.add_row("Mode", f"[bold magenta]MICRO[/bold magenta] [dim]— single tool:[/dim] [white]{micro}[/white]")
    else:
        body.add_row("Mode", "[bold white]FULL PIPELINE[/bold white] [dim]— phases 1 → 6[/dim]")
    body.add_row("Target", f"[bold white]{target}[/bold white] [dim]({target_type})[/dim]")
    if not micro:
        body.add_row("Profile", f"[bold white]{profile}[/bold white]")
        body.add_row("", f"[dim]{profile_desc}[/dim]")
        body.add_row("Threads", f"[white]{threads}[/white] concurrent module(s) in Phase 3")
    body.add_row("Output", f"[white]{output_dir}[/white]")

    if htb:
        body.add_row("HTB mode", "[bold green]ENABLED[/bold green] [dim]— hostname → /etc/hosts → notes.md[/dim]")
    if creds:
        body.add_row("Credentials", "[bold yellow]PROVIDED[/bold yellow] [dim]— credentialed AD collection unlocked[/dim]")

    if attacker_ip:
        body.add_row("Attacker IP", f"[bold white]{attacker_ip}[/bold white] [dim]({attacker_iface})[/dim]")
    else:
        body.add_row("Attacker IP", "[yellow]not detected — connect your VPN before scanning[/yellow]")

    if resume:
        body.add_row("Resume", "[bold yellow]ON[/bold yellow] [dim]— skipping modules already completed[/dim]")

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
    table = Table(
        box=SIMPLE, show_edge=False, pad_edge=False,
        title="[bold cyan]Phase 3 — triggered modules[/bold cyan]",
    )
    table.add_column("✓", width=2)
    table.add_column("Module", style="bold cyan")
    table.add_column("Triggered because", style="dim")

    for spec in specs:
        table.add_row("○", spec.name, spec.description or "—")

    with _console_lock:
        console.print(table)
        console.print()


# ── End-of-scan dashboard ──────────────────────────────────────────
def end_summary_panel(state: "RVRState", elapsed_seconds: int):
    """Closing dashboard: risk badge, severity distribution, services,
    top findings, AD intel and deliverables — everything the operator needs
    to decide the next move without opening the report."""
    # Local import: findings pulls in the report data-model; keeping it out
    # of module scope avoids any import-order surprises for console users.
    from rvr.output.findings import FindingsBuilder

    builder = FindingsBuilder(state)
    findings = builder.build()
    counts = builder.counts()
    risk = state.ai_risk_level or builder.overall_risk()

    mins, secs = divmod(elapsed_seconds, 60)
    elapsed_str = f"{mins}m {secs}s" if mins else f"{secs}s"

    # ── header band ──────────────────────────────────────────────
    header = Table.grid(padding=(0, 1))
    header.add_column(justify="center")
    header.add_column(justify="center")
    header.add_column(justify="center")
    header.add_column(justify="center")

    risk_style = SEV_STYLE.get(risk, "bold white")
    header.add_row(
        f"[bold white]{state.target}[/bold white]",
        "·",
        f"[{risk_style}]{(state.hostname or state.target_type).upper()}[/{risk_style}]",
        f"[dim]{elapsed_str} · {len(state.completed_modules)} modules[/dim]",
    )

    sev_parts = []
    for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
        if counts.get(sev, 0):
            sev_parts.append(f"[{SEV_STYLE[sev]}]{SEV_ICON[sev]} {counts[sev]}[/{SEV_STYLE[sev]}]")
    sev_line = ("  ".join(sev_parts) if sev_parts
                else f"[green]{SEV_ICON['Informational']} no findings flagged[/green]")

    top_body = Table.grid(padding=(0, 2))
    top_body.add_column(style="bold cyan", justify="right")
    top_body.add_column()
    top_body.add_row("Risk", f"[{risk_style}]■ {risk.upper()}[/{risk_style}]")
    top_body.add_row("Findings", f"{sev_line}  [dim]({len(findings)} total)[/dim]")
    if state.failed_modules:
        top_body.add_row("Failed", f"[yellow]{', '.join(state.failed_modules)}[/yellow]")

    # ── services dashboard ───────────────────────────────────────
    body_rows = [top_body]
    if state.open_ports:
        services = Table(
            box=SIMPLE, show_edge=False, pad_edge=False, padding=(0, 1),
            title="[bold cyan]Services[/bold cyan]",
        )
        services.add_column("PORT", width=9, justify="right", style="bold white")
        services.add_column("SERVICE", style="cyan")
        services.add_column("VERSION", style="dim", overflow="fold")
        for p in sorted(state.open_ports, key=lambda x: x["port"])[:12]:
            services.add_row(f"{p['port']}/{p['proto']}", p["service"], (p.get("version") or "")[:48])
        if len(state.open_ports) > 12:
            services.caption = f"... and {len(state.open_ports) - 12} more — Appendix A"
        body_rows.append(services)

    # ── top findings ─────────────────────────────────────────────
    top_findings = [f for f in findings if f.severity in ("Critical", "High")][:5]
    if not top_findings:
        top_findings = findings[:3]
    if top_findings:
        lines = Table.grid(padding=(0, 1))
        lines.add_column(width=3, justify="center")
        lines.add_column(overflow="fold")
        for f in top_findings:
            lines.add_row(f"[{SEV_STYLE[f.severity]}]{SEV_ICON[f.severity]}[/{SEV_STYLE[f.severity]}]",
                          f"[bold]{f.title}[/bold] [dim]· {f.affected}[/dim]")
        wrapped = Table.grid(padding=(1, 0))
        wrapped.add_column()
        wrapped.add_row(Text("Top findings", style="bold cyan"))
        wrapped.add_row(lines)
        body_rows.append(wrapped)

    # ── AD / attack intel line ───────────────────────────────────
    intel = []
    if state.get_domain():
        intel.append(f"domain [bold white]{state.get_domain()}[/bold white]")
    if state.smb_findings.get("spray_hits"):
        intel.append("[bold red]valid credentials[/bold red]")
    if state.kerberos_findings.get("asrep_roast", {}).get("count"):
        intel.append(f"[red]{state.kerberos_findings['asrep_roast']['count']} AS-REP roastable[/red]")
    if state.kerberos_findings.get("kerberoast", {}).get("count"):
        intel.append(f"[red]{state.kerberos_findings['kerberoast']['count']} kerberoastable[/red]")
    if state.captured_hashes:
        intel.append(f"[yellow]{len(state.captured_hashes)} hash(es) captured[/yellow]")
    if state.exploit_matches:
        uniq = len({m['id'] for m in state.exploit_matches})
        intel.append(f"[red]{uniq} public exploit(s)[/red]")
    if state.adcs_findings.get("vulnerable_templates"):
        intel.append("[red]vulnerable cert templates[/red]")
    if state.vhosts:
        intel.append(f"{len(state.vhosts)} vhost(s)")
    if intel:
        wrapped = Table.grid(padding=(1, 0))
        wrapped.add_column()
        wrapped.add_row(Text("Attack intel", style="bold cyan"))
        wrapped.add_row("  ·  ".join(intel))
        body_rows.append(wrapped)

    # ── deliverables + phase checklist ───────────────────────────
    deliverables = ["report.pdf", "report.md", "raw_data.json"]
    if state.htb_mode:
        deliverables.append("notes.md")
    deliv_line = "  ".join(f"[white]{name}[/white]" for name in deliverables
                           if (state.output_dir / name).exists())
    if deliv_line:
        wrapped = Table.grid(padding=(1, 0))
        wrapped.add_column()
        wrapped.add_row(Text("Deliverables", style="bold cyan"))
        wrapped.add_row(deliv_line)
        body_rows.append(wrapped)

    layout = Table.grid(padding=(1, 0))
    layout.add_column(justify="center")
    for row in body_rows:
        layout.add_row(row)

    with _console_lock:
        console.print()
        console.print(Panel(
            layout,
            title=f"[bold green]Scan Complete[/bold green] [dim]— {elapsed_str}[/dim]",
            border_style="green" if risk in ("Low", "Informational") else
                         ("red" if risk in ("Critical",) else "yellow" if risk == "High" else "blue"),
            box=ROUNDED,
            padding=(1, 2),
        ))
        console.print()


def phase_checklist():
    """Render the recorded section history as a compact checklist — used by
    the CLI's verbose mode and post-run review."""
    if not _phase_log:
        return
    t = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False, padding=(0, 1))
    t.add_column("✓", width=2)
    t.add_column("Phase", style="cyan")
    t.add_column("Started", style="dim", justify="right")
    for title, ts in _phase_log:
        t.add_row("●", title, ts.strftime("%H:%M:%S"))
    with _console_lock:
        console.print(t)
        console.print()
