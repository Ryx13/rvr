"""
RVR — AI Analysis module
Sends structured scan findings to an AI provider (Gemini / Claude / OpenAI —
see ai_providers.py) for CVE correlation and attack-path suggestions.
"""

import json
from typing import Optional

from dotenv import load_dotenv

from rvr.modules.base import BaseModule
from rvr.modules.ai_providers import get_provider
from rvr.utils.console import log_info, log_success, log_warn, log_error
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
        )

    def _build_prompt(self) -> str:
        """Build a structured prompt from all scan data collected so far"""
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
                for f in interesting[:20]
            ])

        nuclei_summary = ""
        if s.nuclei_findings:
            nuclei_summary = f"\nNuclei findings ({len(s.nuclei_findings)}):\n"
            nuclei_summary += "\n".join([
                f"  - [{f.get('info', {}).get('severity', '?').upper()}] "
                f"{f.get('template-id', '?')}: {f.get('matched-at', '?')}"
                for f in s.nuclei_findings[:10]
            ])

        smb_summary = f"\nSMB findings: {json.dumps(s.smb_findings, indent=2)}" if s.smb_findings else ""
        nfs_summary = f"\nNFS mounts: {', '.join(s.nfs_mounts)}" if s.nfs_mounts else ""
        snmp_summary = f"\nSNMP data: {json.dumps(s.snmp_data, indent=2)}" if s.snmp_data else ""
        ftp_summary = f"\nFTP findings: {json.dumps(s.ftp_findings, indent=2)}" if s.ftp_findings else ""
        db_summary = f"\nDatabase findings: {json.dumps(s.database_findings, indent=2)}" if s.database_findings else ""
        ldap_summary = f"\nLDAP findings: {json.dumps(s.ldap_findings, indent=2)}" if s.ldap_findings else ""
        rdp_summary = f"\nRDP findings: {json.dumps(s.rdp_findings, indent=2)}" if s.rdp_findings else ""
        tech_summary = f"\nDetected technologies: {', '.join(s.web_technologies)}" if s.web_technologies else ""

        prompt = f"""You are a penetration testing assistant analysing reconnaissance data.
Analyse the following scan results for target: {s.target}
Profile used: {s.profile}

OPEN PORTS:
{ports_summary if ports_summary else "None discovered"}
{web_summary}
{nuclei_summary}
{smb_summary}
{nfs_summary}
{snmp_summary}
{ftp_summary}
{db_summary}
{ldap_summary}
{rdp_summary}
{tech_summary}

Provide your response in the following JSON format ONLY — no markdown, no preamble:
{{
  "executive_summary": "2-3 sentence overview of the attack surface",
  "risk_level": "Critical|High|Medium|Low",
  "probable_cves": ["CVE-XXXX-XXXX", ...],
  "attack_vectors": [
    "Description of potential attack vector 1",
    "Description of potential attack vector 2"
  ],
  "manual_validation": [
    "Specific command or check to validate finding 1",
    "Specific command or check to validate finding 2"
  ],
  "priority_targets": ["port/service that should be investigated first", ...]
}}"""

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
            self.state.ai_vectors = data.get("attack_vectors", [])
            self.state.ai_risk_level = data.get("risk_level", "Unknown")
            self.state.ai_manual_validation = data.get("manual_validation", [])
            self.state.ai_priority_targets = data.get("priority_targets", [])
            self.state.ai_provider_used = self.provider.name
            self.state.ai_raw = data

            ai_file = self.state.output_dir / "ai_analysis.json"
            with open(ai_file, "w") as f:
                json.dump(data, f, indent=2)
            self.state.add_artifact("ai_analysis", ai_file)

            log_success(f"Risk level: {self.state.ai_risk_level}")

            if self.state.ai_vectors:
                log_success("Attack vectors identified:")
                for v in self.state.ai_vectors[:3]:
                    log_success(f"  → {v}")

            if self.state.ai_cves:
                log_success(f"Probable CVEs: {', '.join(self.state.ai_cves[:5])}")

        except json.JSONDecodeError:
            self.state.ai_summary = response[:1000]
            log_warn("AI response was not valid JSON — stored as raw summary")