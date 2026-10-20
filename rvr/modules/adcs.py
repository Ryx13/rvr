"""
RVR — ADCS / Active Directory Certificate Services module
Checks whether the target exposes an AD CS web enrollment endpoint
(/certsrv) and, if Certipy is installed, enumerates vulnerable certificate
templates — ESC1 through ESC15 misconfigurations are a dominant attack path
in modern AD engagements and appear frequently in HTB AD sets.

Certipy is optional: when absent the module records the exact commands to
run manually, and the /certsrv detection itself still lands in state so the
report can flag exposed web enrollment.
"""

from typing import Dict, Any
from datetime import datetime

import requests

from rvr.modules.base import BaseModule
from rvr.utils.console import log_info, log_warn, console
from rvr.utils.state import RVRState

# Common CA web enrollment paths (HTTP/HTTPS on the DC or dedicated CA server)
CERTSRV_PATHS = ["/certsrv", "/certsrv/default.asp", "/CertSrv/default.asp"]


class ADCSModule(BaseModule):
    def __init__(self, state: RVRState, profile: Dict[str, Any]):
        super().__init__(state, profile)
        self.adcs_dir = self.ensure_dir("adcs")

    def run(self):
        web_ports = self.state.get_web_ports()
        if not web_ports:
            return

        enrollment = self._detect_web_enrollment(web_ports)
        certipy_present = self.tool_exists(self.tool("certipy"))

        if not enrollment and not self.state.looks_like_ad():
            # No certsrv endpoint and no AD indicators — nothing to do
            return

        domain = self.state.get_domain()
        if enrollment:
            self.state.adcs_findings["web_enrollment"] = enrollment

        if not certipy_present:
            if enrollment or domain:
                self._record_manual_commands(domain, enrollment)
            return

        if domain:
            self._run_certipy(domain)

        self._print_summary()

    # ── Detection ────────────────────────────────────────────────
    def _detect_web_enrollment(self, web_ports) -> Dict[str, Any]:
        """Probe /certsrv on each web port — its presence is a finding on
        its own (classic NTLM-relayable endpoint)."""
        console.print("  [cyan]○[/cyan]  ADCS web enrollment detection...", end="\r")
        t0 = datetime.now()

        for port in web_ports:
            proto = "https" if port in [443, 8443] else "http"
            base = f"{proto}://{self.state.target}:{port}"
            for path in CERTSRV_PATHS:
                try:
                    # verify=False is deliberate: recon targets (HTB boxes,
                    # labs, self-signed CA endpoints) routinely present
                    # invalid certs; certificate *validity* is a finding,
                    # not a prerequisite for probing.
                    resp = requests.get(base + path, timeout=10, verify=False,
                                        allow_redirects=True)
                    if resp.status_code in [200, 401, 403] and (
                        "certsrv" in resp.text.lower() or "certificate services" in resp.text.lower()
                        or resp.status_code == 401
                    ):
                        elapsed = (datetime.now() - t0).seconds
                        console.print(
                            f"  [red]✓[/red]  ADCS — web enrollment exposed at {base}{path}  "
                            f"[dim]({elapsed}s)[/dim]"
                        )
                        return {"url": f"{base}{path}", "port": port, "status": resp.status_code}
                except requests.RequestException:
                    continue

        elapsed = (datetime.now() - t0).seconds
        console.print(f"  [dim]✓  ADCS — no web enrollment endpoint  ({elapsed}s)[/dim]")
        return {}

    # ── Certipy enumeration ──────────────────────────────────────
    def _run_certipy(self, domain: str):
        creds = self.state.ad_credentials
        if not creds:
            log_info("Certipy needs credentials (--creds user:pass) for template enumeration — "
                     "manual commands recorded instead")
            self._record_manual_commands(domain, self.state.adcs_findings.get("web_enrollment", {}))
            return

        user, passwd = creds.split(":", 1)
        console.print("  [cyan]○[/cyan]  Certipy vulnerable template enumeration...", end="\r")
        t0 = datetime.now()

        out_file = self.adcs_dir / "certipy_vulnerable.txt"
        cmd = [
            self.tool("certipy"), "find",
            "-vulnerable", "-stdout",
            "-u", f"{user}@{domain}",
            "-p", passwd,
            "-dc-ip", self.state.target,
        ]
        output = self.run_command(cmd, output_file=out_file, timeout=300, silent=True) or ""
        elapsed = (datetime.now() - t0).seconds

        # Certipy marks vulnerable templates with lines like:
        # [!] Vulnerable certificate templates located: ...
        vuln_lines = [l for l in output.splitlines() if "vulnerable" in l.lower() and "[!]" in l]
        esc_refs = sorted(set(
            seg.strip() for l in output.splitlines() for seg in l.split() if seg.upper().startswith("ESC")
        ))

        if vuln_lines or esc_refs:
            self.state.adcs_findings["vulnerable_templates"] = {
                "notes": vuln_lines[:20],
                "esc_classes": esc_refs,
            }
            self.state.add_artifact("certipy_vulnerable", out_file)
            console.print(
                f"  [red]✓[/red]  Certipy — vulnerable templates found "
                f"({' '.join(esc_refs) if esc_refs else 'see output'})  [dim]({elapsed}s)[/dim]"
            )
        else:
            console.print(f"  [dim]✓  Certipy — no vulnerable templates / auth failed  ({elapsed}s)[/dim]")

    # ── Manual fallback ──────────────────────────────────────────
    def _record_manual_commands(self, domain, enrollment):
        if not domain:
            return
        cmds_file = self.adcs_dir / "MANUAL_COMMANDS.md"
        cred_hint = self.state.ad_credentials or "user:pass"
        user = cred_hint.split(":", 1)[0]
        enroll_note = (
            f"Web enrollment detected at {enrollment.get('url')} — also relayable via ntlmrelayx."
            if enrollment else ""
        )
        cmds_file.write_text(f"""# ADCS — manual enumeration commands

Domain: {domain} · DC: {self.state.target}
{enroll_note}

## Install certipy if needed

```bash
pipx install certipy-ad
```

## Enumerate vulnerable templates (needs credentials)

```bash
certipy find -vulnerable -stdout -u '{user}@{domain}' -p '<password>' -dc-ip {self.state.target}
```

## Escalate per ESC class once a vulnerable template is found

```bash
# ESC1 example — enroll in a vulnerable template and request a DA cert
certipy req -u '{user}@{domain}' -p '<password>' -ca '<CA-Name>' -template '<VulnerableTemplate>'
# Then authenticate with the cert (PassTheCert / Schannel)
```
""")
        self.state.adcs_findings["manual_commands"] = str(cmds_file)
        self.state.add_artifact("adcs_manual", cmds_file)

    def _print_summary(self):
        a = self.state.adcs_findings
        if not a:
            return
        console.print()
        console.print("  [bold cyan]ADCS Summary[/bold cyan]")
        if a.get("web_enrollment"):
            console.print(f"  Web enrollment:    [red]exposed — {a['web_enrollment']['url']}[/red]")
        if a.get("vulnerable_templates"):
            escs = " ".join(a["vulnerable_templates"].get("esc_classes", [])) or "see certipy output"
            console.print(f"  Vuln templates:    [red]{escs}[/red]")
        if a.get("manual_commands"):
            console.print(f"  Manual workflow:   [cyan]{a['manual_commands']}[/cyan]")
        console.print()
