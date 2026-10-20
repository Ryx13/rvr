"""
RVR — Web module v4
Auto-filters redirect noise, clean status display, gobuster + ffuf,
SSL certificate mining (SAN hostnames), vHost fuzzing, API endpoint
probing, and a second extension-based ffuf pass on non-stealth profiles.
"""

import json
import re
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
from collections import Counter

import requests
from rich.table import Table

from rvr.modules.base import BaseModule
from rvr.utils.console import log_info, log_success, log_warn, console
from rvr.utils.state import RVRState

# Common API / documentation endpoints worth a cheap direct probe —
# catches Swagger/OpenAPI/GraphQL surfaces that directory wordlists miss.
API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/swagger", "/api/docs",
    "/swagger", "/swagger.json", "/swagger-ui", "/swagger-ui.html",
    "/openapi.json", "/api/openapi.json", "/docs", "/api-docs",
    "/graphql", "/graphiql", "/actuator", "/api/config",
]


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
            if proto == "https":
                self._run_step("SSL certificate mining", self.run_ssl_cert, base_url)
            self._run_step("Screenshot capture", self.run_screenshot, base_url)
            self._run_step("API endpoint probing", self.run_api_probe, base_url)
            self._run_step("ffuf directory fuzzing", self.run_ffuf, f"{base_url}/FUZZ")
            self._run_step("ffuf extension fuzzing", self.run_extension_ffuf, base_url)
            self._run_step("vHost discovery", self.run_vhost_fuzz, base_url)
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

    # ── SSL certificate mining ─────────────────────────────────
    def run_ssl_cert(self, url: str):
        """Pull the server certificate via openssl and mine it for the
        Subject CN, SAN hostnames, issuer and validity window. SAN entries
        on HTB-style targets frequently reveal the machine's real hostname —
        the single most useful value for the /etc/hosts workflow."""
        if not self.tool_exists(self.tool("openssl")):
            return

        host = self.state.target
        port = url.rsplit(":", 1)[-1]
        out_file = self.web_dir / f"ssl_cert_{host}_{port}.txt"

        # -status avoids a hanging OCSP fetch; timeout keeps slow TLS stacks from stalling the phase
        cmd = [
            "bash", "-c",
            f"echo | timeout 15 {self.tool('openssl')} s_client -connect {host}:{port} "
            f"-servername {host} 2>/dev/null "
            f"| {self.tool('openssl')} x509 -noout -text 2>/dev/null"
        ]
        output = self.run_command(cmd, output_file=out_file, timeout=30, silent=True) or ""
        if not output.strip() or "Certificate" not in output:
            return

        cert: Dict[str, Any] = {"port": int(port), "url": url}

        subject = re.search(r"Subject:\s*(.+)", output)
        if subject:
            cert["subject"] = subject.group(1).strip()
            cn = re.search(r"CN\s*=\s*([^,\n]+)", subject.group(1))
            if cn:
                cert["cn"] = cn.group(1).strip()

        issuer = re.search(r"Issuer:\s*(.+)", output)
        if issuer:
            cert["issuer"] = issuer.group(1).strip()

        san = re.search(r"Subject Alternative Name[^\n]*\n?\s*(.+)", output)
        if san:
            entries = [e.strip() for e in re.split(r"[,\n]", san.group(1)) if ":" in e]
            cert["san"] = [e.split(":", 1)[1].strip() for e in entries]

        valid = re.search(r"Not After\s*:\s*(.+)", output)
        if valid:
            cert["valid_to"] = valid.group(1).strip()

        if len(cert) > 2:
            self.state.ssl_certs.append(cert)
            self.state.add_artifact(f"ssl_cert_{port}", out_file)
            if cert.get("san") or cert.get("cn"):
                names = ", ".join((cert.get("san") or []) + ([cert["cn"]] if cert.get("cn") else []))
                console.print(f"      [magenta]cert hostnames: {names}[/magenta]")

    # ── vHost discovery ─────────────────────────────────────
    def run_vhost_fuzz(self, base_url: str):
        """ffuf with a Host-header FUZZ to uncover name-based virtual hosts.
        For domain targets: FUZZ.<domain>. For raw IPs (HTB machines): plain
        FUZZ against a subdomain wordlist — a different response size than
        the default-vhost baseline indicates a dedicated vhost."""
        if not self.tool_exists(self.tool("ffuf")):
            return
        wordlist = self.config.wordlist("vhosts")
        if not wordlist or not Path(wordlist).exists():
            return

        host_base = self.state.target
        if self.state.target_type == "domain":
            host_value = f"FUZZ.{host_base}"
        else:
            host_value = "FUZZ"

        # Baseline: response size for the default host — everything that
        # differs in size is a candidate vhost.
        baseline_size = self._vhost_baseline(base_url)
        if baseline_size is None:
            return

        safe = base_url.replace("://", "_").replace(":", "_")
        out_file = self.web_dir / f"vhosts_{safe[:40]}.json"

        cmd = [
            self.tool("ffuf"), "-u", base_url,
            "-w", wordlist,
            "-H", f"Host: {host_value}",
            "-o", str(out_file), "-of", "json",
            "-rate", str(self.profile["ffuf_rate"]),
            "-mc", "all", "-fc", "404",
            "-fs", str(baseline_size),
            "-t", "50", "-s",
        ]
        self.run_command(cmd, timeout=240, silent=True)

        if out_file.exists():
            findings = self._parse_ffuf_json(out_file)
            for f in findings:
                fuzz_word = f.get("input", {}).get("FUZZ", "?")
                self.state.vhosts.append({
                    "host": fuzz_word,
                    "host_full": host_value.replace("FUZZ", fuzz_word),
                    "status": f["status"],
                    "size": f.get("size", 0),
                })
            if self.state.vhosts:
                self.state.add_artifact(f"vhosts_{safe[:30]}", out_file)

    def _vhost_baseline(self, base_url: str) -> Optional[int]:
        """Response size when requesting with the default Host header —
        the baseline that vHost candidates must differ from."""
        try:
            # verify=False is deliberate — recon targets routinely present
            # self-signed certs (see run_ssl_cert).
            resp = requests.get(base_url, timeout=10, verify=False, allow_redirects=False)
            return len(resp.content)
        except requests.RequestException:
            return None

    # ── API endpoint probing ─────────────────────────────────
    def run_api_probe(self, base_url: str):
        """Direct GET against common API/documentation endpoints. Hits like
        swagger.json / openapi.json / graphql land in web_findings tagged
        source='api-probe' so they surface in the report's web tables."""
        for path in API_PATHS:
            url = base_url.rstrip("/") + path
            try:
                # verify=False: see run_ssl_cert — probing self-signed recon targets
                resp = requests.get(url, timeout=8, verify=False, allow_redirects=False)
                if resp.status_code in [200, 201, 204, 401, 403] and resp.status_code != 404:
                    if resp.status_code != 403 or "api" in path:  # 403 only counts for explicit API paths
                        self.state.web_findings.append({
                            "url": url,
                            "status": resp.status_code,
                            "size": len(resp.content),
                            "words": 0,
                            "source": "api-probe",
                        })
            except requests.RequestException:
                continue

    # ── Extension fuzzing pass ─────────────────────────────────
    def run_extension_ffuf(self, base_url: str):
        """Second ffuf pass appending common file extensions. Tuned per
        profile via config.yaml's web_extensions (empty = disabled, which
        is the stealth default)."""
        if not self.tool_exists(self.tool("ffuf")):
            return
        extensions = (self.config.web_extensions or {}).get(self.state.profile, "")
        if not extensions:
            return
        self.run_ffuf(url=f"{base_url}/FUZZ", extensions=extensions)

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