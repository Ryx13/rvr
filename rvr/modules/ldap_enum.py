"""
RVR — LDAP / Active Directory module
Anonymous bind check against RootDSE, naming context discovery, and a light
anonymous user/group enumeration pass if the bind succeeds. Uses `ldapsearch`
(OpenLDAP client tools) — present by default on Kali.
"""

import re
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

from rvr.modules.base import BaseModule
from rvr.utils.console import log_success, log_warn, console
from rvr.utils.state import RVRState


class LDAPModule(BaseModule):
    def __init__(self, state: RVRState, profile: Dict[str, Any]):
        super().__init__(state, profile)
        self.ldap_dir = self.ensure_dir("ldap")

    def run(self):
        if not self.tool_exists("ldapsearch"):
            log_warn("ldapsearch not found (install ldap-utils)")
            return

        port = 636 if self.state.has_port(636) and not self.state.has_port(389) else 389
        uri = f"{'ldaps' if port in (636, 3269) else 'ldap'}://{self.state.target}"

        console.print("  [cyan]○[/cyan]  LDAP anonymous bind + RootDSE...", end="\r")
        t0 = datetime.now()

        rootdse_file = self.ldap_dir / "rootdse.txt"
        cmd = ["ldapsearch", "-x", "-H", uri, "-s", "base", "-b", "", "(objectClass=*)", "+"]
        output = self.run_command(cmd, output_file=rootdse_file, timeout=30, silent=True) or ""
        elapsed = (datetime.now() - t0).seconds

        anon_bind = "result: 0 Success" in output or "namingContexts" in output
        self.state.ldap_findings["anonymous_bind"] = anon_bind
        self.state.add_artifact("ldap_rootdse", rootdse_file)

        naming_contexts = re.findall(r"namingContexts:\s*(.+)", output)
        default_context = re.findall(r"defaultNamingContext:\s*(.+)", output)
        domain = re.findall(r"ldapServiceName:\s*([\w.\-]+)", output)

        if naming_contexts:
            self.state.ldap_findings["naming_contexts"] = [c.strip() for c in naming_contexts]
        if default_context:
            self.state.ldap_findings["default_naming_context"] = default_context[0].strip()
        if domain:
            self.state.ldap_findings["domain"] = domain[0].strip()

        if anon_bind:
            console.print(f"  [red]✓[/red]  LDAP — anonymous bind ALLOWED  [dim]({elapsed}s)[/dim]")
            self._enumerate_anonymous()
        else:
            console.print(f"  [dim]✗  LDAP — anonymous bind denied  ({elapsed}s)[/dim]")

        self._print_summary()

    def _enumerate_anonymous(self):
        base = self.state.ldap_findings.get("default_naming_context") or \
            (self.state.ldap_findings.get("naming_contexts", [None])[0])
        if not base:
            return

        port = 636 if self.state.has_port(636) and not self.state.has_port(389) else 389
        uri = f"{'ldaps' if port in (636, 3269) else 'ldap'}://{self.state.target}"

        console.print(f"  [cyan]○[/cyan]  LDAP anonymous enumeration (base: {base})...", end="\r")
        t0 = datetime.now()

        out_file = self.ldap_dir / "anon_enum.txt"
        cmd = [
            "ldapsearch", "-x", "-H", uri, "-b", base,
            "(|(objectClass=user)(objectClass=group))",
            "sAMAccountName", "objectClass",
        ]
        output = self.run_command(cmd, output_file=out_file, timeout=60, silent=True) or ""
        elapsed = (datetime.now() - t0).seconds

        users = list(set(re.findall(r"sAMAccountName:\s*(.+)", output)))
        self.state.ldap_findings["anonymous_users"] = [u.strip() for u in users]
        self.state.add_artifact("ldap_anon_enum", out_file)

        console.print(f"  [green]✓[/green]  LDAP anon enum — {len(users)} account(s)  [dim]({elapsed}s)[/dim]")

    def _print_summary(self):
        d = self.state.ldap_findings
        if not d:
            return
        console.print()
        console.print("  [bold cyan]LDAP Summary[/bold cyan]")
        color = "red" if d.get("anonymous_bind") else "green"
        console.print(f"  Anonymous bind:   [{color}]{'ALLOWED' if d.get('anonymous_bind') else 'DENIED'}[/{color}]")
        if d.get("domain"):
            console.print(f"  Domain:           [cyan]{d['domain']}[/cyan]")
        if d.get("default_naming_context"):
            console.print(f"  Naming context:   [cyan]{d['default_naming_context']}[/cyan]")
        if d.get("anonymous_users"):
            shown = ", ".join(d["anonymous_users"][:10])
            console.print(f"  Accounts found:   [yellow]{shown}[/yellow]")
        console.print()