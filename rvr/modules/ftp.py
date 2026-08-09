"""
RVR — FTP module
Anonymous login check, banner grab, and anon-accessible directory listing.
Uses Python's stdlib ftplib — no external binary required.
"""

import socket
import ftplib
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

from rvr.modules.base import BaseModule
from rvr.utils.console import log_success, log_warn, console
from rvr.utils.state import RVRState


class FTPModule(BaseModule):
    def __init__(self, state: RVRState, profile: Dict[str, Any]):
        super().__init__(state, profile)
        self.ftp_dir = self.ensure_dir("ftp")

    def run(self):
        console.print("  [cyan]○[/cyan]  FTP banner + anonymous login check...", end="\r")
        t0 = datetime.now()

        banner = self._grab_banner()
        anon_ok, listing = self._check_anonymous()

        elapsed = (datetime.now() - t0).seconds

        self.state.ftp_findings["banner"] = banner
        self.state.ftp_findings["anonymous_login"] = anon_ok
        if listing:
            self.state.ftp_findings["anon_listing"] = listing

        out_file = self.ftp_dir / "ftp_enum.txt"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w") as f:
            f.write(f"Banner: {banner}\n")
            f.write(f"Anonymous login: {anon_ok}\n")
            if listing:
                f.write("\nDirectory listing (anonymous):\n")
                f.write("\n".join(listing))
        self.state.add_artifact("ftp_enum", out_file)

        if anon_ok:
            console.print(f"  [green]✓[/green]  FTP — anonymous login ALLOWED  [dim]({elapsed}s)[/dim]")
        else:
            console.print(f"  [dim]✗  FTP — anonymous login denied  ({elapsed}s)[/dim]")

        self._print_summary()

    def _grab_banner(self) -> str:
        try:
            with socket.create_connection((self.state.target, 21), timeout=10) as sock:
                sock.settimeout(10)
                data = sock.recv(1024)
                return data.decode(errors="replace").strip()
        except Exception:
            return ""

    def _check_anonymous(self):
        listing: List[str] = []
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.state.target, 21, timeout=15)
            ftp.login("anonymous", "anonymous@rvr.local")
            try:
                listing = ftp.nlst()
            except ftplib.error_perm:
                listing = []
            ftp.quit()
            return True, listing
        except Exception:
            return False, listing

    def _print_summary(self):
        f = self.state.ftp_findings
        if not f:
            return
        console.print()
        console.print("  [bold cyan]FTP Summary[/bold cyan]")
        if f.get("banner"):
            console.print(f"  Banner:           [cyan]{f['banner'][:100]}[/cyan]")
        color = "red" if f.get("anonymous_login") else "green"
        console.print(f"  Anonymous login:  [{color}]{'ALLOWED' if f.get('anonymous_login') else 'DENIED'}[/{color}]")
        if f.get("anon_listing"):
            log_warn(f"  {len(f['anon_listing'])} item(s) visible via anonymous FTP — see ftp/ftp_enum.txt")
        console.print()