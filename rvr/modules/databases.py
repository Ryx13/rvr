"""
RVR — Database module
Uses targeted Nmap NSE scripts per detected DB port rather than pulling in
heavyweight DB client libraries — keeps RVR's "orchestrate, don't reimplement"
philosophy for a category of service that's easy to get wrong by hand-rolling
protocol clients.

Covers: MySQL (3306), MSSQL (1433), Redis (6379), MongoDB (27017).
PostgreSQL (5432) has no reliable unauthenticated NSE probe beyond service
detection (already captured by the network module), so it's recorded as
"detected — needs manual credential testing" rather than actively probed.
"""

from pathlib import Path
from typing import Dict, Any
from datetime import datetime

from rvr.modules.base import BaseModule
from rvr.utils.console import log_warn, console
from rvr.utils.state import RVRState


DB_PORTS = {
    3306: "mysql",
    1433: "mssql",
    5432: "postgresql",
    6379: "redis",
    27017: "mongodb",
}

NSE_SCRIPTS = {
    3306: "mysql-info,mysql-empty-password",
    1433: "ms-sql-info,ms-sql-empty-password,ms-sql-config",
    6379: "redis-info",
    27017: "mongodb-info",
}


class DatabaseModule(BaseModule):
    def __init__(self, state: RVRState, profile: Dict[str, Any]):
        super().__init__(state, profile)
        self.db_dir = self.ensure_dir("databases")

    def run(self):
        if not self.tool_exists("nmap"):
            log_warn("nmap not found — cannot probe databases")
            return

        open_ports = set(self.state.get_open_port_numbers())
        targets = {p: name for p, name in DB_PORTS.items() if p in open_ports}
        if not targets:
            return

        for port, name in targets.items():
            console.print(f"  [cyan]○[/cyan]  Database probe — {name}:{port}...", end="\r")
            t0 = datetime.now()

            if port == 5432:
                self.state.database_findings[name] = {
                    "port": port,
                    "note": "PostgreSQL detected — no safe unauthenticated NSE probe; test credentials manually",
                }
                elapsed = (datetime.now() - t0).seconds
                console.print(f"  [yellow]![/yellow]  {name}:{port} detected — manual credential test needed  [dim]({elapsed}s)[/dim]")
                continue

            out_file = self.db_dir / f"{name}.txt"
            cmd = [
                "nmap", "-p", str(port),
                "--script", NSE_SCRIPTS[port],
                self.state.target,
            ]
            output = self.run_command(cmd, output_file=out_file, timeout=90, silent=True)
            elapsed = (datetime.now() - t0).seconds

            finding = self._parse(name, output or "")
            finding["port"] = port
            self.state.database_findings[name] = finding
            self.state.add_artifact(f"db_{name}", out_file)

            if finding.get("empty_password") or finding.get("unauthenticated"):
                console.print(f"  [red]✓[/red]  {name}:{port} — misconfiguration found  [dim]({elapsed}s)[/dim]")
            else:
                console.print(f"  [green]✓[/green]  {name}:{port} probed  [dim]({elapsed}s)[/dim]")

        self._print_summary()

    def _parse(self, name: str, output: str) -> Dict[str, Any]:
        finding: Dict[str, Any] = {}
        lower = output.lower()

        if name == "mysql":
            finding["empty_password"] = "root account has empty password" in lower or "vulnerable" in lower
        elif name == "mssql":
            finding["empty_password"] = "empty password" in lower and "account" in lower
        elif name == "redis":
            # redis-info succeeding at all with no auth prompt means it's open with no auth
            finding["unauthenticated"] = "redis_version" in lower or "unauthenticated" in lower
        elif name == "mongodb":
            finding["unauthenticated"] = "mongodb" in lower and "server version" in lower

        for line in output.splitlines():
            line = line.strip()
            if line and not line.startswith(("Starting Nmap", "Nmap scan", "PORT", "Host is up", "Nmap done")):
                finding.setdefault("notes", []).append(line)

        return finding

    def _print_summary(self):
        d = self.state.database_findings
        if not d:
            return
        console.print()
        console.print("  [bold cyan]Database Summary[/bold cyan]")
        for name, finding in d.items():
            flagged = finding.get("empty_password") or finding.get("unauthenticated")
            color = "red" if flagged else "cyan"
            status = "misconfigured / unauthenticated access" if flagged else "detected"
            console.print(f"  {name:<12} [{color}]{status}[/{color}]  (port {finding.get('port')})")
        console.print()