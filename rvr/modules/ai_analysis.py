"""
RVR — AI Analysis module
Uses Gemini API to analyse scan results and generate insights
"""

import os
import json
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

from rvr.modules.base import BaseModule
from rvr.utils.console import log_info, log_success, log_warn, log_error
from rvr.utils.state import RVRState

load_dotenv()


class AIModule(BaseModule):
    def __init__(self, state: RVRState):
        super().__init__(state, {})
        self.api_key = os.getenv("GEMINI_API_KEY")

    def run(self):
        """Generate AI analysis of scan results"""
        if not self.api_key:
            log_warn("GEMINI_API_KEY not set in .env — skipping AI analysis")
            return

        if not self.state.open_ports and not self.state.web_findings:
            log_warn("No scan data to analyse — skipping AI analysis")
            return

        log_info("Sending scan data to Gemini for analysis...")

        prompt = self._build_prompt()
        response = self._query_gemini(prompt)

        if response:
            self._parse_response(response)
            log_success("AI analysis complete")
            if self.state.ai_summary:
                log_info(f"Summary: {self.state.ai_summary[:200]}...")
        else:
            log_warn("AI analysis failed or returned no response")

    def _build_prompt(self) -> str:
        """Build a structured prompt from scan data"""
        s = self.state

        # Summarise open ports
        ports_summary = "\n".join([
            f"  - {p['port']}/{p['proto']}: {p['service']} {p['version']}"
            for p in s.open_ports
        ])

        # Summarise web findings
        web_summary = ""
        if s.web_findings:
            interesting = [f for f in s.web_findings if f["status"] in [200, 201, 401, 403]]
            web_summary = f"\nInteresting web paths ({len(interesting)} found):\n"
            web_summary += "\n".join([
                f"  - [{f['status']}] {f['url']}"
                for f in interesting[:20]
            ])

        # Nuclei findings
        nuclei_summary = ""
        if s.nuclei_findings:
            nuclei_summary = f"\nNuclei findings ({len(s.nuclei_findings)}):\n"
            nuclei_summary += "\n".join([
                f"  - [{f.get('info', {}).get('severity', '?').upper()}] "
                f"{f.get('template-id', '?')}: {f.get('matched-at', '?')}"
                for f in s.nuclei_findings[:10]
            ])

        # SMB findings
        smb_summary = ""
        if s.smb_findings:
            smb_summary = f"\nSMB findings: {json.dumps(s.smb_findings, indent=2)}"

        # Technologies
        tech_summary = ""
        if s.web_technologies:
            tech_summary = f"\nDetected technologies: {', '.join(s.web_technologies)}"

        prompt = f"""You are a penetration testing assistant analysing reconnaissance data.
Analyse the following scan results for target: {s.target}
Profile used: {s.profile}

OPEN PORTS:
{ports_summary if ports_summary else "None discovered"}
{web_summary}
{nuclei_summary}
{smb_summary}
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

    def _query_gemini(self, prompt: str) -> Optional[str]:
        """Send prompt to Gemini API and return response"""
        try:
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=self.api_key)

            response = client.models.generate_content(
                model="gemini-2.0-flash",
                contents=prompt,
            )
            return response.text

        except ImportError:
            log_error("google-genai not installed. Run: pip install google-genai")
            return None
        except Exception as e:
            log_error(f"Gemini API error: {e}")
            return None

    def _parse_response(self, response: str):
        """Parse Gemini JSON response into state"""
        # Strip any markdown code blocks if present
        response = response.strip()
        if response.startswith("```"):
            lines = response.split("\n")
            response = "\n".join(lines[1:-1])

        try:
            data = json.loads(response)

            self.state.ai_summary = data.get("executive_summary", "")
            self.state.ai_cves = data.get("probable_cves", [])
            self.state.ai_vectors = data.get("attack_vectors", [])

            # Store full response in state
            self.state.smb_findings["ai_full"] = data

            # Save to file
            ai_file = self.state.output_dir / "ai_analysis.json"
            with open(ai_file, "w") as f:
                json.dump(data, f, indent=2)
            self.state.add_artifact("ai_analysis", ai_file)

            # Log key findings
            risk = data.get("risk_level", "Unknown")
            log_success(f"Risk level: {risk}")

            vectors = data.get("attack_vectors", [])
            if vectors:
                log_success("Attack vectors identified:")
                for v in vectors[:3]:
                    log_success(f"  → {v}")

            cves = data.get("probable_cves", [])
            if cves:
                log_success(f"Probable CVEs: {', '.join(cves[:5])}")

        except json.JSONDecodeError:
            # If JSON parsing fails, store raw response as summary
            self.state.ai_summary = response[:1000]
            log_warn("AI response was not valid JSON — stored as raw summary")
