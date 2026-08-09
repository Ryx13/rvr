"""
RVR — Web module v3
Auto-filters redirect noise, clean status display, gobuster + ffuf
"""

import json
import re
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
from collections import Counter

from rich.table import Table

from rvr.modules.base import BaseModule
from rvr.utils.console import log_info, log_success, log_warn, log_error, console
from rvr.utils.state import RVRState


class WebModule(BaseModule):
    def __init__(self, state: RVRState, profile: Dict[str, Any]):
        super().__init__(state, profile)
        self.web_dir = self.ensure_dir("web")

    def run(self):
        web_ports = self.state.get_web_ports()
        if not web_ports:
            log_warn("No web ports found — skipping web module")
            return

        for port in web_ports:
            proto = "https" if port in [443, 8443] else "http"
            base_url = f"{proto}://{self.state.target}:{port}"

            console.print(f"  [bold cyan]Web target:[/bold cyan] {base_url}")
            console.print()

            self._run_step("WhatWeb fingerprinting", self.run_whatweb, base_url)
            self._run_step("Screenshot capture", self.run_screenshot, base_url)
            self._run_step("ffuf directory fuzzing", self.run_ffuf, f"{base_url}/FUZZ")
            self._run_step("Gobuster brute-force", self.run_gobuster, base_url)
            self._run_step("Nuclei vulnerability scan", self.run_nuclei, base_url)

            console.print()
            self._print_results()

        log_success(f"Web enumeration complete on {len(web_ports)} port(s)")

    def _run_step(self, name: str, fn, *args):
        """Run a web sub-task with clean status output"""
        console.print(f"  [cyan]○[/cyan]  {name}...", end="\r")
        t0 = datetime.now()
        fn(*args)
        elapsed = (datetime.now() - t0).seconds
        elapsed_str = f"{elapsed}s" if elapsed < 60 else f"{elapsed//60}m {elapsed%60}s"
        console.print(f"  [green]✓[/green]  {name}  [dim]({elapsed_str})[/dim]")

    def run_whatweb(self, base_url: Optional[str] = None):
        if not self.tool_exists(self.tool("whatweb")):
            return
        if not base_url:
            base_url = self._default_url()
        out_file = self.web_dir / "whatweb.txt"
        cmd = [self.tool("whatweb"), "--color=never", "-a", "3", base_url]
        output = self.run_command(cmd, output_file=out_file, timeout=60, silent=True)
        if output:
            techs = self._parse_whatweb(output)
            self.state.web_technologies.extend(techs)
            self.state.add_artifact("whatweb", out_file)

    def run_ffuf(
        self,
        url: Optional[str] = None,
        wordlist: Optional[str] = None,
        extensions: str = "",
        extra_flags: str = "",
    ):
        if not self.tool_exists(self.tool("ffuf")):
            return
        if not url:
            url = f"{self._default_url()}/FUZZ"
        if not wordlist:
            wordlist = self.config.wordlist("web_common") or "/usr/share/seclists/Discovery/Web-Content/common.txt"

        safe_url = url.replace("://", "_").replace("/", "_").replace(":", "_")
        out_file = self.web_dir / f"ffuf_{safe_url[:50]}.json"

        cmd = [
            self.tool("ffuf"), "-u", url,
            "-w", wordlist,
            "-o", str(out_file), "-of", "json",
            "-rate", str(self.profile["ffuf_rate"]),
            "-mc", "all", "-fc", "404",
            "-t", "50", "-s",
        ]

        if extensions:
            cmd.extend(["-e", f".{extensions.replace(',', ',.')}"])

        self.run_command(cmd, timeout=300, silent=True)

        if out_file.exists():
            findings = self._parse_ffuf_json(out_file)
            # Auto-detect and filter redirect noise
            findings = self._filter_redirect_noise(findings)
            self.state.web_findings.extend(findings)
            self.state.add_artifact(f"ffuf_{safe_url[:30]}", out_file)

    def run_gobuster(self, base_url: Optional[str] = None) -> int:
        if not self.tool_exists(self.tool("gobuster")):
            return 0
        if not base_url:
            base_url = self._default_url()

        wordlist = self.config.wordlist("web_medium") or "/usr/share/seclists/Discovery/Web-Content/big.txt"
        out_file = self.web_dir / "gobuster.txt"
        cmd = [
            self.tool("gobuster"), "dir",
            "-u", base_url,
            "-w", wordlist,
            "-o", str(out_file),
            "-q", "-t", "50", "--no-error",
            "-b", "404,429",
        ]

        self.run_command(cmd, timeout=300, silent=True)

        count = 0
        if out_file.exists():
            with open(out_file) as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith("Error")]

            for line in lines:
                match = re.match(r'^(/\S+)\s+\(Status:\s*(\d+)\)', line)
                if match:
                    path, status = match.groups()
                    self.state.web_findings.append({
                        "url": base_url + path,
                        "status": int(status),
                        "size": 0,
                        "words": 0,
                        "source": "gobuster",
                    })
                    count += 1

            self.state.add_artifact("gobuster", out_file)

        return count

    def run_nuclei(self, target: Optional[str] = None, choice: str = "1"):
        if not self.tool_exists(self.tool("nuclei")):
            return
        if not target:
            target = self._default_url()

        safe = target.replace("://", "_").replace("/", "_").replace(":", "_")
        out_file = self.web_dir / f"nuclei_{safe[:50]}.json"

        cmd = [
            self.tool("nuclei"), "-u", target,
            "-o", str(out_file),
            "-json", "-silent", "-no-color",
        ]

        if choice == "2":
            cmd.extend(["-t", "cves/"])
        elif choice == "3":
            cmd.extend(["-severity", "critical,high"])

        self.run_command(cmd, timeout=300, silent=True)

        if out_file.exists():
            findings = self._parse_nuclei_json(out_file)
            self.state.nuclei_findings.extend(findings)
            self.state.add_artifact(f"nuclei_{safe[:30]}", out_file)

    def run_screenshot(self, url: Optional[str] = None):
        """Capture a screenshot of the target web port via gowitness (v3 CLI)."""
        if not self.tool_exists(self.tool("gowitness")):
            return
        if not url:
            url = self._default_url()

        shots_dir = self.ensure_dir("web/screenshots")
        safe = url.replace("://", "_").replace("/", "_").replace(":", "_")
        jsonl_file = self.web_dir / f"gowitness_{safe[:50]}.jsonl"

        cmd = [
            self.tool("gowitness"), "scan", "single",
            "--url", url,
            "--screenshot-path", str(shots_dir),
            "--write-jsonl",
            "--write-jsonl-file", str(jsonl_file),
        ]
        self.run_command(cmd, timeout=90, silent=True)

        shot_path = self._find_screenshot(shots_dir, url)
        if shot_path:
            self.state.screenshots.append({"url": url, "path": str(shot_path)})
            self.state.add_artifact(f"screenshot_{safe[:30]}", shot_path)
        if jsonl_file.exists():
            self.state.add_artifact(f"gowitness_jsonl_{safe[:30]}", jsonl_file)

    def _find_screenshot(self, shots_dir: Path, url: str) -> Optional[Path]:
        """gowitness names screenshots by a hash of the URL; grab the most
        recently written file in the target dir rather than guessing the name."""
        try:
            files = [p for p in shots_dir.glob("*.jpeg")] + [p for p in shots_dir.glob("*.png")]
            if not files:
                return None
            return max(files, key=lambda p: p.stat().st_mtime)
        except Exception:
            return None

    def _filter_redirect_noise(self, findings: List[Dict]) -> List[Dict]:
        """
        Auto-detect mass redirects to the same destination
        (e.g. everything redirects to /login) and filter them out,
        keeping only the unique ones.
        """
        if not findings:
            return findings

        # Count redirect destinations
        redirects = [f.get("redirect", "") for f in findings if f.get("status") in [301, 302, 307]]
        if not redirects:
            return findings

        redirect_counts = Counter(redirects)
        most_common_redirect, count = redirect_counts.most_common(1)[0]

        # If more than 80% of findings redirect to the same place, it's noise
        noise_threshold = len(findings) * 0.8
        if count >= noise_threshold and most_common_redirect:
            log_warn(
                f"Mass redirect detected → {most_common_redirect} "
                f"({count} paths) — filtering noise"
            )
            # Keep only non-redirect findings and unique redirects
            filtered = [
                f for f in findings
                if f.get("status") not in [301, 302, 307]
                or f.get("redirect") != most_common_redirect
            ]
            log_info(f"Filtered {len(findings) - len(filtered)} noisy redirects — {len(filtered)} real findings remain")
            return filtered

        return findings

    def _print_results(self):
        """Print clean web results tables"""
        if self.state.web_technologies:
            tech_str = ", ".join(
                t for t in self.state.web_technologies
                if t and len(t) > 1 and "RESERVED" not in t
            )
            if tech_str:
                console.print(f"  [bold]Technologies:[/bold] [cyan]{tech_str}[/cyan]")
                console.print()

        findings = self.state.web_findings
        if not findings:
            log_warn("No web findings to display")
            return

        # Separate by status category
        interesting = [f for f in findings if f["status"] in [200, 201, 204]]
        redirects   = [f for f in findings if f["status"] in [301, 302, 307]]
        forbidden   = [f for f in findings if f["status"] in [401, 403]]
        errors      = [f for f in findings if f["status"] >= 500]

        def make_table(title: str, rows: List[Dict], color: str) -> Table:
            t = Table(
                title=f"[bold]{title}[/bold]",
                show_header=True,
                header_style=f"bold {color}",
                border_style=f"dim {color}",
                show_lines=False,
                padding=(0, 1),
            )
            t.add_column("STATUS", width=8, justify="center")
            t.add_column("URL")
            t.add_column("SIZE", width=8, justify="right")
            t.add_column("SRC", width=9)

            for f in rows[:50]:
                t.add_row(
                    f"[{color}]{f['status']}[/{color}]",
                    f["url"][:85],
                    str(f.get("size", "")),
                    f.get("source", "ffuf"),
                )
            return t

        if interesting:
            console.print(make_table(f"✓ 2xx — Accessible ({len(interesting)})", interesting, "green"))
            console.print()
        if forbidden:
            console.print(make_table(f"🔒 4xx — Forbidden/Auth ({len(forbidden)})", forbidden, "yellow"))
            console.print()
        if redirects:
            console.print(make_table(f"↪ 3xx — Redirects ({len(redirects)})", redirects[:20], "blue"))
            if len(redirects) > 20:
                console.print(f"  [dim]... and {len(redirects)-20} more redirects[/dim]")
            console.print()
        if errors:
            console.print(make_table(f"⚠ 5xx — Server Errors ({len(errors)})", errors, "red"))
            console.print()

        # Nuclei
        if self.state.nuclei_findings:
            n_table = Table(
                title=f"[bold red]Nuclei Findings ({len(self.state.nuclei_findings)})[/bold red]",
                show_header=True,
                header_style="bold red",
                border_style="red",
                show_lines=False,
            )
            n_table.add_column("SEVERITY", width=10)
            n_table.add_column("TEMPLATE", width=30)
            n_table.add_column("MATCHED AT")
            sev_colors = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow", "LOW": "green", "INFO": "blue"}
            for f in self.state.nuclei_findings:
                sev = f.get("info", {}).get("severity", "?").upper()
                color = sev_colors.get(sev, "white")
                n_table.add_row(
                    f"[{color}]{sev}[/{color}]",
                    f.get("template-id", "?"),
                    f.get("matched-at", "?"),
                )
            console.print(n_table)
            console.print()

    def _default_url(self) -> str:
        web_ports = self.state.get_web_ports()
        port = web_ports[0] if web_ports else 80
        proto = "https" if port in [443, 8443] else "http"
        return f"{proto}://{self.state.target}:{port}"

    def _parse_whatweb(self, output: str) -> List[str]:
        techs = []
        matches = re.findall(r'\[([^\[\]]+?)\]', output)
        for m in matches:
            if not any(c.isdigit() for c in m[:3]) and len(m) > 2:
                techs.append(m.split("[")[0].strip())
        return list(set(techs))

    def _parse_ffuf_json(self, json_file: Path) -> List[Dict[str, Any]]:
        findings = []
        try:
            with open(json_file) as f:
                data = json.load(f)
            for result in data.get("results", []):
                findings.append({
                    "url": result.get("url", ""),
                    "status": result.get("status", 0),
                    "size": result.get("length", 0),
                    "words": result.get("words", 0),
                    "redirect": result.get("redirectlocation", ""),
                    "source": "ffuf",
                })
        except Exception as e:
            log_warn(f"Failed to parse ffuf output: {e}")
        return findings

    def _parse_nuclei_json(self, json_file: Path) -> List[Dict[str, Any]]:
        findings = []
        try:
            with open(json_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        findings.append(json.loads(line))
        except Exception as e:
            log_warn(f"Failed to parse nuclei output: {e}")
        return findings