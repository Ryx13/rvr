"""
RVR — AI Analysis module
Sends structured scan findings to an AI provider (Gemini / Claude / OpenAI —
see ai_providers.py) for CVE correlation and attack-path suggestions.
"""

import json

from dotenv import load_dotenv

from rvr.modules.base import BaseModule
from rvr.modules.ai_providers import get_provider
from rvr.utils.console import log_info, log_success, log_warn
from rvr.utils.state import RVRState

load_dotenv()


class AIModule(BaseModule):
    def __init__(self, state: RVRState):
        super().__init__(state, {})
        self.provider = get_provider()

    def run(self):
        """Generate AI analysis of scan results"""
        if not self.provider:
            log_warn(
                "No AI provider configured — set GEMINI_API_KEY, ANTHROPIC_API_KEY, "
                "or OPENAI_API_KEY in .env — skipping AI analysis"
            )
            return

        if not self._has_data():
            log_warn("No scan data to analyse — skipping AI analysis")
            return

        log_info(f"Sending scan data to {self.provider.name} ({self.provider.model}) for analysis...")

        prompt = self._build_prompt()
        response = self.provider.query(prompt)

        if response:
            self._parse_response(response)
            log_success("AI analysis complete")
            if self.state.ai_summary:
                log_info(f"Summary: {self.state.ai_summary[:200]}...")
        else:
            log_warn("AI analysis failed or returned no response")

    def _has_data(self) -> bool:
        s = self.state
        return bool(
            s.open_ports or s.web_findings or s.ftp_findings
            or s.database_findings or s.ldap_findings or s.rdp_findings
            or s.kerberos_findings or s.bloodhound_findings or s.adcs_findings
            or s.exploit_matches or s.captured_hashes or s.nuclei_findings
        )

    def _build_prompt(self) -> str:
        """Build a structured prompt from all scan data collected so far."""
        s = self.state

        ports_summary = "\n".join([
            f"  - {p['port']}/{p['proto']}: {p['service']} {p.get('version', '')}"
            for p in s.open_ports
        ])

        web_summary = ""
        if s.web_findings:
            interesting = [f for f in s.web_findings if f["status"] in [200, 201, 401, 403]]
            web_summary = f"\nInteresting web paths ({len(interesting)} found):\n"
            web_summary += "\n".join([
                f"  - [{f['status']}] {f['url']}"
                for f in interesting[:25]
            ])

        nuclei_summary = ""
        if s.nuclei_findings:
            nuclei_summary = f"\nNuclei findings ({len(s.nuclei_findings)}):\n"
            nuclei_summary += "\n".join([
                f"  - [{f.get('info', {}).get('severity', '?').upper()}] "
                f"{f.get('template-id', '?')}: {f.get('matched-at', '?')}"
                for f in s.nuclei_findings[:15]
            ])

        exploits_summary = ""
        if s.exploit_matches:
            exploits_summary = f"\nPublic exploits matched from Exploit-DB ({len(s.exploit_matches)}):\n"
            exploits_summary += "\n".join([
                f"  - Port {m['port']} [{m['query']}]: EDB-{m['id']} {m['title']} ({m['type']})"
                for m in s.exploit_matches[:20]
            ])

        smb_summary = f"\nSMB findings: {json.dumps(s.smb_findings, indent=2)}" if s.smb_findings else ""
        nfs_summary = f"\nNFS mounts: {', '.join(s.nfs_mounts)}" if s.nfs_mounts else ""
        snmp_summary = f"\nSNMP data: {json.dumps(s.snmp_data, indent=2)}" if s.snmp_data else ""
        ftp_summary = f"\nFTP findings: {json.dumps(s.ftp_findings, indent=2)}" if s.ftp_findings else ""
        db_summary = f"\nDatabase findings: {json.dumps(s.database_findings, indent=2)}" if s.database_findings else ""
        ldap_summary = f"\nLDAP findings: {json.dumps(s.ldap_findings, indent=2)}" if s.ldap_findings else ""
        rdp_summary = f"\nRDP findings: {json.dumps(s.rdp_findings, indent=2)}" if s.rdp_findings else ""
        krb_summary = f"\nKerberos findings: {json.dumps(s.kerberos_findings, indent=2)}" if s.kerberos_findings else ""
        bh_summary = f"\nBloodHound: {json.dumps(s.bloodhound_findings, indent=2)}" if s.bloodhound_findings else ""
        adcs_summary = f"\nADCS findings: {json.dumps(s.adcs_findings, indent=2)}" if s.adcs_findings else ""
        tech_summary = f"\nDetected technologies: {', '.join(s.web_technologies)}" if s.web_technologies else ""
        vhost_summary = f"\nVirtual hosts: {', '.join(v.get('host_full', v.get('host', '?')) for v in s.vhosts[:15])}" if s.vhosts else ""
        hostname_summary = f"\nDiscovered hostname: {s.hostname} (sources: {', '.join(s.hostname_sources)})" if s.hostname else ""

        hashes_summary = ""
        if s.captured_hashes:
            hashes_summary = f"\nCaptured crackable hashes ({len(s.captured_hashes)}):\n"
            hashes_summary += "\n".join([
                f"  - [{h['type']}] {h['account']}"
                for h in s.captured_hashes[:15]
            ])

        prompt = f"""You are a senior penetration tester analysing reconnaissance data for a
{self.state.profile}-profile engagement. Target: {s.target} ({s.target_type}).
Your analysis will be embedded into a commercial-grade assessment report read by
both executives and engineers, and your next-steps will guide hands-on testing.

TARGET CONTEXT
{hostname_summary}{vhost_summary}

OPEN PORTS & SERVICES
{ports_summary if ports_summary else "None discovered"}

ENUMERATION RESULTS{tech_summary}{web_summary}{nuclei_summary}{exploits_summary}{hashes_summary}{smb_summary}{nfs_summary}{snmp_summary}{ftp_summary}{db_summary}{ldap_summary}{rdp_summary}{krb_summary}{bh_summary}{adcs_summary}

Respond with ONLY a JSON object (no markdown fences, no prose outside the JSON)
using exactly this schema:
{{
  "executive_summary": "3-6 sentence business-language overview of this target's security posture: what an attacker could reach, and what the overall risk picture is. Written for a non-technical executive.",
  "risk_level": "Critical|High|Medium|Low",
  "risk_justification": "2-3 sentences explaining WHY this risk level was chosen, citing the strongest drivers.",
  "findings": [
    {{
      "title": "Short finding title",
      "severity": "Critical|High|Medium|Low|Informational",
      "category": "Misconfiguration|Vulnerable Service|Exposed Data|Weak Authentication|Attack Surface",
      "description": "What was observed and why it matters (2-4 sentences).",
      "evidence": "The concrete observation this is based on (ports, banners, tool output).",
      "remediation": "Specific, actionable fix guidance (2-4 sentences).",
      "cves": ["CVE-XXXX-XXXX"]
    }}
  ],
  "attack_paths": [
    {{
      "name": "Attack path name",
      "mitre": "TXXXX technique name",
      "steps": ["Step 1", "Step 2", "Step 3"],
      "prerequisites": "What an attacker needs to start this path",
      "impact": "What they achieve if it succeeds"
    }}
  ],
  "next_steps": [
    "Prioritized, concrete next action for the operator — include exact commands where useful"
  ],
  "probable_cves": ["CVE-XXXX-XXXX"],
  "priority_targets": ["port/service to investigate first and why"]
}}

Rules:
- Base every finding on OBSERVED data above — never invent open ports or services.
- Include 3-10 findings, ordered by severity (most severe first).
- Include 1-4 attack paths chaining the observed weaknesses into realistic routes.
- next_steps: 3-8 items, ordered by expected value, with copy-pasteable commands.
- Map attack paths to MITRE ATT&CK technique IDs where applicable."""

        return prompt

    def _parse_response(self, response: str):
        """Parse the provider's JSON response into state"""
        response = response.strip()
        if response.startswith("```"):
            lines = response.split("\n")
            response = "\n".join(lines[1:-1])

        try:
            data = json.loads(response)

            self.state.ai_summary = data.get("executive_summary", "")
            self.state.ai_cves = data.get("probable_cves", [])
            self.state.ai_vectors = [
                p.get("name", "") for p in data.get("attack_paths", [])
                if isinstance(p, dict)
            ] or data.get("attack_vectors", [])
            self.state.ai_risk_level = data.get("risk_level", "Unknown")
            self.state.ai_risk_justification = data.get("risk_justification")
            self.state.ai_manual_validation = data.get("next_steps", [])
            self.state.ai_priority_targets = data.get("priority_targets", [])
            self.state.ai_findings = data.get("findings", [])
            self.state.ai_attack_paths = data.get("attack_paths", [])
            self.state.ai_next_steps = data.get("next_steps", [])
            self.state.ai_provider_used = self.provider.name
            self.state.ai_raw = data

            ai_file = self.state.output_dir / "ai_analysis.json"
            with open(ai_file, "w") as f:
                json.dump(data, f, indent=2)
            self.state.add_artifact("ai_analysis", ai_file)

            log_success(f"Risk level: [bold]{self.state.ai_risk_level}[/bold]")

            if self.state.ai_findings:
                sev_colors = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "green"}
                log_success(f"{len(self.state.ai_findings)} finding(s) drafted:")
                for f in self.state.ai_findings[:5]:
                    sev = str(f.get("severity", "?")).lower()
                    color = sev_colors.get(sev, "white")
                    log_success(f"  → [{color}][{f.get('severity', '?')}][/{color}] {f.get('title', '?')}")

            if self.state.ai_attack_paths:
                log_success("Attack paths:")
                for p in self.state.ai_attack_paths[:3]:
                    mitre = f" [dim]({p.get('mitre', '')})[/dim]" if p.get("mitre") else ""
                    log_success(f"  → {p.get('name', '?')}{mitre}")

            if self.state.ai_cves:
                log_success(f"Probable CVEs: {', '.join(self.state.ai_cves[:8])}")

        except json.JSONDecodeError:
            self.state.ai_summary = response[:1000]
            log_warn("AI response was not valid JSON — stored as raw summary")