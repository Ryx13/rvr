"""
RVR — SMB module v2
"""

import json
import re
from pathlib import Path
from typing import Dict, Any, List

from rvr.modules.base import BaseModule
from rvr.utils.console import log_warn, console
from rvr.utils.state import RVRState


class SMBModule(BaseModule):
    def __init__(self, state: RVRState, profile: Dict[str, Any]):
        super().__init__(state, profile)
        self.smb_dir = self.ensure_dir("smb")

    def run(self):
        from datetime import datetime
        console.print("  [cyan]○[/cyan]  enum4linux-ng full SMB enumeration...", end="\r")
        t0 = datetime.now()
        self._run_enum4linux()
        elapsed = (datetime.now() - t0).seconds
        console.print(f"  [green]✓[/green]  enum4linux-ng complete  [dim]({elapsed}s)[/dim]")

        console.print("  [cyan]○[/cyan]  NetExec anonymous checks...", end="\r")
        t1 = datetime.now()
        self.run_netexec(choice="1")
        self.run_netexec(choice="2")
        elapsed2 = (datetime.now() - t1).seconds
        console.print(f"  [green]✓[/green]  NetExec complete  [dim]({elapsed2}s)[/dim]")

        self._print_smb_summary()

    def _run_enum4linux(self):
        if not self.tool_exists(self.tool("enum4linux")):
            log_warn("enum4linux-ng not found")
            return

        out_file = self.smb_dir / "enum4linux.txt"
        json_base = str(self.smb_dir / "enum4linux")

        cmd = [self.tool("enum4linux"), "-A", "-oJ", json_base, self.state.target]
        self.run_command(cmd, output_file=out_file, timeout=300, silent=True)

        json_out = Path(json_base + ".json")
        if json_out.exists():
            self._parse_enum4linux_json(json_out)
            self.state.add_artifact("enum4linux_json", json_out)
        self.state.add_artifact("enum4linux_txt", out_file)

    def run_netexec(self, choice: str = "1"):
        if not self.tool_exists(self.tool("netexec")):
            return

        if choice == "1":
            out_file = self.smb_dir / "netexec_anon.txt"
            cmd = [self.tool("netexec"), "smb", self.state.target, "-u", "", "-p", ""]
            output = self.run_command(cmd, output_file=out_file, timeout=60, silent=True)
            if output:
                if "Signing:" in output:
                    self.state.smb_findings["signing"] = "enabled" if "True" in output else "disabled"
                self.state.smb_findings["anonymous_login"] = "[+]" in output

        elif choice == "2":
            out_file = self.smb_dir / "netexec_shares.txt"
            cmd = [self.tool("netexec"), "smb", self.state.target, "-u", "", "-p", "", "--shares"]
            output = self.run_command(cmd, output_file=out_file, timeout=60, silent=True)
            if output:
                shares = self._parse_shares(output)
                self.state.smb_findings["shares"] = shares
            self.state.add_artifact("netexec_shares", out_file)

        elif choice == "3":
            out_file = self.smb_dir / "netexec_rid.txt"
            cmd = [self.tool("netexec"), "smb", self.state.target, "-u", "", "-p", "", "--rid-brute"]
            output = self.run_command(cmd, output_file=out_file, timeout=120, silent=True)
            if output:
                users = self._parse_rid_users(output)
                self.state.smb_findings["users"] = users
            self.state.add_artifact("netexec_rid", out_file)

    def _print_smb_summary(self):
        smb = self.state.smb_findings
        if not smb:
            return

        console.print()
        console.print("  [bold cyan]SMB Summary[/bold cyan]")

        if "signing" in smb:
            color = "red" if smb["signing"] == "disabled" else "green"
            console.print(f"  Signing:          [{color}]{smb['signing']}[/{color}]")
        if "anonymous_login" in smb:
            val = smb["anonymous_login"]
            color = "red" if val else "green"
            console.print(f"  Anonymous login:  [{color}]{'ALLOWED' if val else 'DENIED'}[/{color}]")
        if smb.get("shares"):
            console.print(f"  Shares:           [yellow]{', '.join(smb['shares'])}[/yellow]")
        if smb.get("users"):
            console.print(f"  Users:            [cyan]{', '.join(smb['users'][:10])}[/cyan]")
        console.print()

    def _parse_enum4linux_json(self, json_file: Path):
        try:
            with open(json_file) as f:
                data = json.load(f)
            if "users" in data:
                self.state.smb_findings["users"] = list(data["users"].keys())
            if "shares" in data:
                self.state.smb_findings["shares"] = list(data["shares"].keys())
            if "os_info" in data:
                self.state.smb_findings["os"] = data["os_info"]
            if "domain_info" in data:
                self.state.smb_findings["domain"] = data["domain_info"]
        except Exception as e:
            log_warn(f"Failed to parse enum4linux JSON: {e}")

    def _parse_shares(self, output: str) -> List[str]:
        shares = []
        for line in output.splitlines():
            if any(x in line for x in ["READ", "WRITE", "NO ACCESS"]):
                parts = line.split()
                for i, p in enumerate(parts):
                    if p in ["READ,WRITE", "READ", "WRITE", "NO"] and i > 0:
                        shares.append(parts[i-1])
        return list(set(shares))

    def _parse_rid_users(self, output: str) -> List[str]:
        users = []
        for line in output.splitlines():
            match = re.search(r'\\(\w+)\s+\(SidTypeUser\)', line)
            if match:
                users.append(match.group(1))
        return users