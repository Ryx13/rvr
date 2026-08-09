"""
RVR — OSINT module v2
"""

import requests
import xml.etree.ElementTree as ET
from typing import Dict, Any
from datetime import datetime

from rvr.modules.base import BaseModule
from rvr.utils.console import log_warn, console
from rvr.utils.state import RVRState


class OSINTModule(BaseModule):
    def __init__(self, state: RVRState, profile: Dict[str, Any]):
        super().__init__(state, profile)
        self.passive_dir = self.ensure_dir("passive")

    def run(self):
        self._step("subfinder subdomain discovery", self.run_subfinder)
        self._step("crt.sh certificate transparency", self._run_crtsh)
        self._step("theHarvester email harvest", self._run_theharvester)

        console.print(
            f"  [green]✓[/green]  OSINT complete — "
            f"[bold]{len(self.state.subdomains)} subdomains[/bold], "
            f"[bold]{len(self.state.emails)} emails[/bold]"
        )
        console.print()

    def _step(self, name: str, fn):
        console.print(f"  [cyan]○[/cyan]  {name}...", end="\r")
        t0 = datetime.now()
        fn()
        elapsed = (datetime.now() - t0).seconds
        console.print(f"  [green]✓[/green]  {name}  [dim]({elapsed}s)[/dim]")

    def run_subfinder(self):
        if not self.tool_exists(self.tool("subfinder")):
            return
        out_file = self.passive_dir / "subdomains.txt"
        cmd = [self.tool("subfinder"), "-d", self.state.target, "-o", str(out_file), "-silent"]
        self.run_command(cmd, timeout=120, silent=True)
        if out_file.exists():
            with open(out_file) as f:
                subs = [l.strip() for l in f if l.strip()]
            self.state.subdomains.extend(subs)
            self.state.add_artifact("subdomains", out_file)

    def _run_crtsh(self):
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{self.state.target}&output=json",
                timeout=30,
            )
            if resp.status_code == 200:
                domains = set()
                for entry in resp.json():
                    for d in entry.get("name_value", "").split("\n"):
                        d = d.strip().lstrip("*.")
                        if self.state.target in d:
                            domains.add(d)
                new = [d for d in domains if d not in self.state.subdomains]
                self.state.subdomains.extend(new)
                out_file = self.passive_dir / "crtsh.txt"
                out_file.write_text("\n".join(sorted(domains)))
                self.state.add_artifact("crtsh", out_file)
        except Exception as e:
            log_warn(f"crt.sh failed: {e}")

    def _run_theharvester(self):
        if not self.tool_exists(self.tool("theharvester")):
            return
        out_file = self.passive_dir / "harvester.xml"
        cmd = [
            self.tool("theharvester"), "-d", self.state.target,
            "-b", "google,bing,duckduckgo",
            "-f", str(out_file),
        ]
        self.run_command(cmd, timeout=120, silent=True)
        xml_file = out_file.with_suffix(".xml")
        if xml_file.exists():
            try:
                tree = ET.parse(xml_file)
                emails = [e.text.strip() for e in tree.findall(".//email") if e.text]
                self.state.emails.extend(emails)
                if emails:
                    (self.passive_dir / "emails.txt").write_text("\n".join(emails))
                    self.state.add_artifact("emails", self.passive_dir / "emails.txt")
            except Exception:
                pass
        self.state.add_artifact("harvester", out_file)