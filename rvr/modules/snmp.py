"""
RVR — SNMP module v2
"""

from typing import Dict, Any
from datetime import datetime

from rvr.modules.base import BaseModule
from rvr.utils.console import log_warn, console
from rvr.utils.state import RVRState


class SNMPModule(BaseModule):
    def __init__(self, state: RVRState, profile: Dict[str, Any]):
        super().__init__(state, profile)
        self.snmp_dir = self.ensure_dir("snmp")

    def run(self):
        if not self.tool_exists(self.tool("snmpwalk")):
            log_warn("snmpwalk not found")
            return

        communities = ["public", "private", "community"]
        for community in communities:
            console.print(f"  [cyan]○[/cyan]  SNMP community '{community}'...", end="\r")
            t0 = datetime.now()
            out_file = self.snmp_dir / f"snmpwalk_{community}.txt"
            cmd = [self.tool("snmpwalk"), "-v2c", "-c", community, self.state.target]
            output = self.run_command(cmd, output_file=out_file, timeout=60, silent=True)
            elapsed = (datetime.now() - t0).seconds

            if output and "Timeout" not in output and "No Such Object" not in output and len(output) > 50:
                console.print(f"  [green]✓[/green]  SNMP '{community}' responded  [dim]({elapsed}s)[/dim]")
                self.state.snmp_data["community"] = community
                self.state.add_artifact(f"snmp_{community}", out_file)
                self._parse_snmp(output)
                self._print_snmp_summary()
                break
            else:
                console.print(f"  [dim]✗  SNMP '{community}' — no response[/dim]")

    def _parse_snmp(self, output: str):
        for line in output.splitlines():
            if "sysDescr" in line:
                self.state.snmp_data["system"] = line.split("=")[-1].strip()
            elif "sysName" in line:
                self.state.snmp_data["hostname"] = line.split("=")[-1].strip()
            elif "sysContact" in line:
                self.state.snmp_data["contact"] = line.split("=")[-1].strip()
            elif "sysLocation" in line:
                self.state.snmp_data["location"] = line.split("=")[-1].strip()

    def _print_snmp_summary(self):
        d = self.state.snmp_data
        console.print()
        if d.get("system"):
            console.print(f"  System:    [cyan]{d['system'][:80]}[/cyan]")
        if d.get("hostname"):
            console.print(f"  Hostname:  [cyan]{d['hostname']}[/cyan]")
        if d.get("contact"):
            console.print(f"  Contact:   [cyan]{d['contact']}[/cyan]")
        console.print()