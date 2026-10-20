"""
RVR — BloodHound collection module
Runs bloodhound-python against the target when an AD-like port layout is
detected, producing a ZIP of collection data ready for BloodHound CE ingest.

Anonymous collection is attempted first (works against permissive
configurations); with --creds user:pass it authenticates properly.
Even when collection fails, the module records the exact commands the
operator should run once credentials are obtained — attack-path mapping is
the single highest-value post-foothold activity in AD environments (CPTS).
"""

from pathlib import Path
from typing import Dict, Any
from datetime import datetime

from rvr.modules.base import BaseModule
from rvr.utils.console import log_info, log_warn, log_success, console
from rvr.utils.state import RVRState


class BloodHoundModule(BaseModule):
    def __init__(self, state: RVRState, profile: Dict[str, Any]):
        super().__init__(state, profile)
        self.bh_dir = self.ensure_dir("bloodhound")

    def run(self):
        domain = self.state.get_domain()
        if not domain:
            log_warn("No AD domain identified — BloodHound collection skipped "
                     "(needs LDAP/RDP/SMB findings to resolve the domain name)")
            return
        if not self.tool_exists(self.tool("bloodhound")):
            log_warn(
                f"{self.tool('bloodhound')} not found — install with: "
                "pipx install bloodhound (or pip install bloodhound)"
            )
            self._record_manual_commands(domain, reason="tool missing")
            return

        collected = self._run_collection(domain, anonymous=True)

        if not collected and self.state.ad_credentials:
            collected = self._run_collection(domain, anonymous=False)

        if not collected:
            self._record_manual_commands(
                domain,
                reason="anonymous collection denied — rerun with --creds once a valid account is found",
            )

        self._print_summary()

    # ── Collection ───────────────────────────────────────────────
    def _run_collection(self, domain: str, anonymous: bool) -> bool:
        creds = "" if anonymous else self.state.ad_credentials
        label = "anonymous" if anonymous else "credentialed"
        collectors = self.config.active_directory.get("bloodhound_collectors", "All")

        console.print(f"  [cyan]○[/cyan]  BloodHound collection ({label})...", end="\r")
        t0 = datetime.now()

        zip_path = self.bh_dir / f"bloodhound_{label}.zip"
        cmd = [
            self.tool("bloodhound"),
            "-d", domain,
            "-dc-ip", self.state.target,
            "-c", collectors,
            "--zip",
            "-o", str(zip_path.with_suffix("")),
        ]
        if anonymous:
            # Empty username against a permissive DC can still dump the domain
            cmd += ["-u", "", "-p", "", "-ns", self.state.target]
        else:
            user, passwd = creds.split(":", 1)
            cmd += ["-u", user, "-p", passwd]

        output = self.run_command(cmd, timeout=420, silent=True) or ""
        elapsed = (datetime.now() - t0).seconds

        # bloodhound-python writes <output>*.zip or a single zip depending on version
        zips = sorted(self.bh_dir.glob("bloodhound*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
        if zips and zips[0].stat().st_size > 100:
            latest = zips[0]
            self.state.bloodhound_findings = {
                "zip_path": str(latest),
                "domain": domain,
                "collectors": collectors,
                "mode": label,
            }
            self.state.add_artifact("bloodhound_zip", latest)
            console.print(
                f"  [green]✓[/green]  BloodHound — collection data saved "
                f"[dim]({elapsed}s)[/dim]"
            )
            return True

        if "failed" in output.lower() or not output.strip():
            console.print(f"  [dim]✓  BloodHound — {label} collection failed  ({elapsed}s)[/dim]")
        else:
            console.print(f"  [dim]✓  BloodHound — {label} collection produced no data  ({elapsed}s)[/dim]")
        return False

    # ── Manual fallback ──────────────────────────────────────────
    def _record_manual_commands(self, domain: str, reason: str):
        """Persist the exact commands to run by hand once creds exist."""
        cmds_file = self.bh_dir / "MANUAL_COMMANDS.md"
        creds_hint = self.state.ad_credentials or "user:pass"
        user, _pass = (creds_hint.split(":", 1) + [""])[:2]
        cmds_file.write_text(f"""# BloodHound — manual collection commands

Reason: {reason}

## 1. Collect (from any foothold or directly against the DC)

```bash
bloodhound-python -d {domain} -dc-ip {self.state.target} -c All -u '{user}' -p '<password>'
```

## 2. Ingest

1. Start BloodHound CE: `docker compose up` (bloodhound-ce quickstart)
2. Upload every `*.json` produced above via **Upload Data** in the UI

## 3. Priority pre-built queries

- `MATCH (u:User) RETURN u` — list users
- Shortest path to Domain Admins from the current user (right-click → *Shortest Paths to Domain Admins*)
- Kerberoastable users: `MATCH (u:User {donotreqpreauth: false}) WHERE u.hasspn RETURN u`
- AS-REP roastable: `MATCH (u:User {donotreqpreauth: true}) RETURN u`
- Unconstrained delegation: `MATCH (c:Computer {unconstraineddelegation: true}) RETURN c`
- GPO abuse / ACL abuse paths from owned principals
""")
        self.state.bloodhound_findings = {
            "domain": domain,
            "manual_commands": str(cmds_file),
            "note": reason,
        }
        self.state.add_artifact("bloodhound_manual", cmds_file)
        log_info(f"BloodHound manual workflow saved: {cmds_file}")

    def _print_summary(self):
        bh = self.state.bloodhound_findings
        if not bh:
            return
        console.print()
        console.print("  [bold cyan]BloodHound Summary[/bold cyan]")
        if bh.get("zip_path"):
            console.print(f"  Collection:        [green]{bh['mode']} — ready for ingest[/green]")
            console.print(f"  Data ZIP:          [cyan]{bh['zip_path']}[/cyan]")
            console.print(f"  Domain:            [cyan]{bh['domain']}[/cyan]")
        elif bh.get("manual_commands"):
            console.print(f"  Collection:        [yellow]deferred — run manually with creds[/yellow]")
            console.print(f"  Workflow notes:    [cyan]{bh['manual_commands']}[/cyan]")
        console.print()
