"""
RVR — Network module v3
Clean output, no raw command spam, proper status display
"""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, List
import os
import time

from rich.table import Table

from rvr.modules.base import BaseModule
from rvr.utils.console import log_info, log_success, log_warn, log_error, console
from rvr.utils.state import RVRState


class NetworkModule(BaseModule):
    def __init__(self, state: RVRState, profile: Dict[str, Any]):
        super().__init__(state, profile)
        self.net_dir = self.ensure_dir("network")

    def run(self, extra_flags: str = ""):
        from datetime import datetime

        # Step 1 — Quick port discovery
        console.print("  [cyan]○[/cyan]  Port discovery scanning 1-65535...", end="\r")
        t0 = datetime.now()
        open_ports = self._quick_scan()
        elapsed = (datetime.now() - t0).seconds
        elapsed_str = f"{elapsed//60}m {elapsed%60}s" if elapsed >= 60 else f"{elapsed}s"

        if not open_ports:
            console.print(f"  [yellow]⚠[/yellow]  Port discovery complete — no open ports found  [dim]({elapsed_str})[/dim]")
            return

        console.print(
            f"  [green]✓[/green]  Port discovery — "
            f"[bold yellow]{len(open_ports)} open ports[/bold yellow]  "
            f"[dim]({elapsed_str})[/dim]"
        )
        console.print()

        # Step 2 — Service detection
        console.print("  [cyan]○[/cyan]  Service & version detection...", end="\r")
        t1 = datetime.now()
        self._service_scan(open_ports, extra_flags)
        elapsed2 = (datetime.now() - t1).seconds
        elapsed2_str = f"{elapsed2//60}m {elapsed2%60}s" if elapsed2 >= 60 else f"{elapsed2}s"

        console.print(
            f"  [green]✓[/green]  Service detection complete  "
            f"[dim]({elapsed2_str})[/dim]"
        )
        console.print()

        # Print results table
        self._print_port_table()

    def _quick_scan(self) -> List[int]:
        ports = self.state.port_override or "1-65535"
        xml_out = self.net_dir / "quick_scan.xml"

        cmd = [
            self.tool("nmap"), "-p", ports,
            f"-T{self.profile['nmap_timing']}",
            "--open", "-oX", str(xml_out),
            "-n", "--min-rate", "1000",
            self.state.target,
        ]

        if os.geteuid() != 0:
            cmd = ["sudo"] + cmd

        # Run with longer timeout for full port scan
        self.run_command(cmd, timeout=600, silent=True)

        if not xml_out.exists():
            return []
        return self._parse_open_ports_xml(xml_out)

    def _service_scan(self, open_ports: List[int], extra_flags: str = ""):
        port_str = ",".join(map(str, open_ports))
        xml_out = self.net_dir / "scan.xml"
        nmap_out = self.net_dir / "scan.nmap"

        cmd = [
            self.tool("nmap"), "-p", port_str,
            "-sV", "-sC",
            f"-T{self.profile['nmap_timing']}",
            "-oX", str(xml_out),
            "-oN", str(nmap_out),
            self.state.target,
        ]

        if os.geteuid() != 0:
            cmd = ["sudo"] + cmd

        if extra_flags:
            cmd = cmd[:-1] + extra_flags.split() + [self.state.target]

        self.run_command(cmd, timeout=900, silent=True)

        if xml_out.exists():
            self._parse_service_xml(xml_out)
            self.state.add_artifact("nmap_xml", xml_out)
            self.state.add_artifact("nmap_nmap", nmap_out)

    def _print_port_table(self):
        if not self.state.open_ports:
            return

        table = Table(
            show_header=True,
            header_style="bold white on blue",
            border_style="dim blue",
            show_lines=True,
            padding=(0, 1),
        )
        table.add_column("PORT", style="bold yellow", width=8, justify="right")
        table.add_column("PROTO", width=6)
        table.add_column("SERVICE", style="bold green", width=14)
        table.add_column("VERSION / BANNER", style="white")

        service_colors = {
            "ssh": "cyan", "http": "green", "https": "green",
            "ftp": "yellow", "smb": "red", "rdp": "red",
            "pop3": "blue", "imap": "blue", "smtp": "blue",
            "nfs": "magenta", "mysql": "yellow", "mssql": "yellow",
        }

        for p in sorted(self.state.open_ports, key=lambda x: x["port"]):
            svc = p["service"]
            color = service_colors.get(svc.lower(), "white")
            table.add_row(
                str(p["port"]),
                p["proto"].upper(),
                f"[{color}]{svc}[/{color}]",
                p.get("version", "")[:70],
            )

        console.print(table)
        console.print()

    def _parse_open_ports_xml(self, xml_file: Path) -> List[int]:
        ports = []
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            for port in root.findall(".//port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    ports.append(int(port.get("portid")))
        except Exception as e:
            log_warn(f"Failed to parse nmap XML: {e}")
        return sorted(ports)

    def _parse_service_xml(self, xml_file: Path):
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            for port in root.findall(".//port"):
                state_elem = port.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue

                port_num = int(port.get("portid"))
                proto = port.get("protocol", "tcp")

                service_elem = port.find("service")
                service_name = "unknown"
                version = ""

                if service_elem is not None:
                    service_name = service_elem.get("name", "unknown")
                    product = service_elem.get("product", "")
                    ver = service_elem.get("version", "")
                    extra = service_elem.get("extrainfo", "")
                    version = f"{product} {ver} {extra}".strip()

                scripts = {}
                for script in port.findall("script"):
                    scripts[script.get("id")] = script.get("output", "")

                self.state.open_ports.append({
                    "port": port_num,
                    "proto": proto,
                    "service": service_name,
                    "version": version,
                    "scripts": scripts,
                })

        except Exception as e:
            log_warn(f"Failed to parse service XML: {e}")


    def run_udp(self, top_ports: int = 200):
        """Run a UDP scan on top ports"""
        import os
        console.print("  [cyan]○[/cyan]  UDP scan (top 200)...", end="\r")
        from datetime import datetime
        t0 = datetime.now()
        xml_out = self.net_dir / "udp_scan.xml"
        nmap_out = self.net_dir / "udp_scan.nmap"

        cmd = [
            self.tool("nmap"), "-sU",
            "--top-ports", str(top_ports),
            f"-T{self.profile['nmap_timing']}",
            "-oX", str(xml_out),
            "-oN", str(nmap_out),
            self.state.target,
        ]
        if os.geteuid() != 0:
            cmd = ["sudo"] + cmd

        self.run_command(cmd, timeout=600, silent=True)
        elapsed = (datetime.now() - t0).seconds
        elapsed_str = f"{elapsed//60}m {elapsed%60}s" if elapsed >= 60 else f"{elapsed}s"

        if xml_out.exists():
            udp_ports = self._parse_open_ports_xml(xml_out)
            if udp_ports:
                console.print(f"  [green]✓[/green]  UDP — {len(udp_ports)} open port(s)  [dim]({elapsed_str})[/dim]")
                # Add UDP ports to state
                self._parse_service_xml(xml_out)
                self.state.add_artifact("udp_xml", xml_out)
            else:
                console.print(f"  [dim]✓  UDP — no open ports  ({elapsed_str})[/dim]")
        else:
            console.print(f"  [yellow]⚠[/yellow]  UDP scan failed")