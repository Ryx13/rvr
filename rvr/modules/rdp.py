"""
RVR — RDP module
Pulls unauthenticated host info (hostname, domain, OS build) via the
rdp-ntlm-info NSE script, checks negotiated security/NLA config via
rdp-enum-encryption, and cross-checks NLA enforcement with NetExec.
None of this requires valid credentials.
"""

import re
from pathlib import Path
from typing import Dict, Any
from datetime import datetime

from rvr.modules.base import BaseModule
from rvr.utils.console import log_warn, console
from rvr.utils.state import RVRState


class RDPModule(BaseModule):
    def __init__(self, state: RVRState, profile: Dict[str, Any]):
        super().__init__(state, profile)
        self.rdp_dir = self.ensure_dir("rdp")

    def run(self):
        if self.tool_exists("nmap"):
            self._run_nmap_scripts()
        else:
            log_warn("nmap not found — skipping RDP NSE probes")

        if self.tool_exists("netexec"):
            self._run_netexec()

        self._print_summary()

    def _run_nmap_scripts(self):
        console.print("  [cyan]○[/cyan]  RDP NTLM info + encryption enum...", end="\r")
        t0 = datetime.now()

        out_file = self.rdp_dir / "nmap_rdp.txt"
        cmd = [
            "nmap", "-p", "3389",
            "--script", "rdp-ntlm-info,rdp-enum-encryption",
            self.state.target,
        ]
        output = self.run_command(cmd, output_file=out_file, timeout=60, silent=True) or ""
        elapsed = (datetime.now() - t0).seconds
        self.state.add_artifact("rdp_nmap", out_file)

        self._parse_ntlm_info(output)
        self._parse_encryption(output)

        console.print(f"  [green]✓[/green]  RDP probes complete  [dim]({elapsed}s)[/dim]")

    def _parse_ntlm_info(self, output: str):
        fields = {
            "Target_Name": "target_name",
            "NetBIOS_Domain_Name": "netbios_domain",
            "NetBIOS_Computer_Name": "netbios_computer",
            "DNS_Domain_Name": "dns_domain",
            "DNS_Computer_Name": "dns_computer",
            "Product_Version": "os_build",
        }
        for label, key in fields.items():
            m = re.search(rf"{label}:\s*(.+)", output)
            if m:
                self.state.rdp_findings[key] = m.group(1).strip()

    def _parse_encryption(self, output: str):
        protocols = re.findall(r"\|\s+(SSL|CredSSP|RDP):", output)
        if protocols:
            self.state.rdp_findings["security_protocols"] = list(set(protocols))
        # NLA is enforced if CredSSP is the (only) offered protocol
        self.state.rdp_findings["nla_likely_required"] = (
            "CredSSP" in protocols and "RDP" not in protocols
        )

    def _run_netexec(self):
        console.print("  [cyan]○[/cyan]  NetExec RDP NLA check...", end="\r")
        t0 = datetime.now()

        out_file = self.rdp_dir / "netexec_rdp.txt"
        cmd = ["netexec", "rdp", self.state.target]
        output = self.run_command(cmd, output_file=out_file, timeout=30, silent=True) or ""
        elapsed = (datetime.now() - t0).seconds
        self.state.add_artifact("rdp_netexec", out_file)

        if "NLA:True" in output.replace(" ", ""):
            self.state.rdp_findings["nla_enabled"] = True
        elif "NLA:False" in output.replace(" ", ""):
            self.state.rdp_findings["nla_enabled"] = False

        console.print(f"  [green]✓[/green]  NetExec RDP check complete  [dim]({elapsed}s)[/dim]")

    def _print_summary(self):
        d = self.state.rdp_findings
        if not d:
            return
        console.print()
        console.print("  [bold cyan]RDP Summary[/bold cyan]")
        if d.get("dns_computer") or d.get("netbios_computer"):
            console.print(f"  Hostname:         [cyan]{d.get('dns_computer') or d.get('netbios_computer')}[/cyan]")
        if d.get("dns_domain") or d.get("netbios_domain"):
            console.print(f"  Domain:           [cyan]{d.get('dns_domain') or d.get('netbios_domain')}[/cyan]")
        if d.get("os_build"):
            console.print(f"  OS build:         [cyan]{d['os_build']}[/cyan]")
        if "nla_enabled" in d:
            color = "green" if d["nla_enabled"] else "red"
            console.print(f"  NLA enforced:     [{color}]{d['nla_enabled']}[/{color}]")
        console.print()