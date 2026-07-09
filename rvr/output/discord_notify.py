"""
RVR — Discord Webhook Notifier
Sends formatted engagement summary to Discord on scan completion
"""

import os
import json
import requests
from datetime import datetime
from typing import Dict, Any, List

from dotenv import load_dotenv
from rvr.utils.console import log_info, log_success, log_warn, log_error
from rvr.utils.state import RVRState

load_dotenv()


class DiscordNotifier:
    def __init__(self, state: RVRState):
        self.state = state
        self.webhook_url = os.getenv("DISCORD_WEBHOOK_URL")

    def send(self):
        if not self.webhook_url:
            log_warn("DISCORD_WEBHOOK_URL not set in .env — skipping notification")
            return

        log_info("Sending Discord notification...")

        payload = self._build_payload()

        try:
            resp = requests.post(
                self.webhook_url,
                json=payload,
                timeout=15,
            )
            if resp.status_code in [200, 204]:
                log_success("Discord notification sent")
            else:
                log_warn(f"Discord returned status {resp.status_code}")
        except Exception as e:
            log_error(f"Discord notification failed: {e}")

    def _build_payload(self) -> Dict[str, Any]:
        s = self.state

        # Risk colour
        risk_colors = {
            "Critical": 0xFF0000,
            "High":     0xFF6B00,
            "Medium":   0xFFD700,
            "Low":      0x00AA00,
            "Unknown":  0x7289DA,
        }

        risk = "Unknown"
        color = risk_colors["Unknown"]

        # Try to get risk from AI analysis
        ai_file = s.output_dir / "ai_analysis.json"
        if ai_file.exists():
            try:
                with open(ai_file) as f:
                    ai_data = json.load(f)
                risk = ai_data.get("risk_level", "Unknown")
                color = risk_colors.get(risk, 0x7289DA)
            except Exception:
                pass

        # Build open ports field
        ports_text = "None discovered"
        if s.open_ports:
            port_lines = [
                f"`{p['port']}/{p['proto']}` {p['service']} {p.get('version','')[:30]}"
                for p in sorted(s.open_ports, key=lambda x: x["port"])[:10]
            ]
            ports_text = "\n".join(port_lines)
            if len(s.open_ports) > 10:
                ports_text += f"\n... and {len(s.open_ports) - 10} more"

        # Build interesting findings field
        findings_text = "None"
        interesting = [f for f in s.web_findings if f["status"] in [200, 201, 401]]
        if interesting:
            findings_lines = [
                f"`[{f['status']}]` {f['url'][:60]}"
                for f in interesting[:8]
            ]
            findings_text = "\n".join(findings_lines)

        # Elapsed time
        elapsed = "N/A"
        try:
            start = datetime.fromisoformat(s.start_time)
            end = datetime.fromisoformat(s.end_time or datetime.now().isoformat())
            elapsed = str(end - start).split(".")[0]
        except Exception:
            pass

        # Build embed
        embed = {
            "title": f"🔍 RVR Scan Complete — {s.target}",
            "color": color,
            "timestamp": datetime.utcnow().isoformat(),
            "footer": {
                "text": "RVR — Ryxvoid Recon Framework"
            },
            "fields": [
                {
                    "name": "📋 Target Info",
                    "value": (
                        f"**Target:** `{s.target}`\n"
                        f"**Type:** {s.target_type}\n"
                        f"**Profile:** {s.profile}\n"
                        f"**Duration:** {elapsed}\n"
                        f"**Risk Level:** {risk}"
                    ),
                    "inline": False,
                },
                {
                    "name": f"🔓 Open Ports ({len(s.open_ports)})",
                    "value": ports_text,
                    "inline": False,
                },
            ]
        }

        # Add web findings if any
        if s.web_findings:
            embed["fields"].append({
                "name": f"🌐 Web Findings ({len(interesting)} interesting)",
                "value": findings_text,
                "inline": False,
            })

        # Add nuclei findings if any
        if s.nuclei_findings:
            critical = [f for f in s.nuclei_findings
                        if f.get("info", {}).get("severity") in ["critical", "high"]]
            embed["fields"].append({
                "name": f"⚠️ Vulnerabilities ({len(s.nuclei_findings)} total)",
                "value": (
                    f"{len(critical)} critical/high severity finding(s)\n"
                    + "\n".join([
                        f"`{f.get('template-id','?')}` — {f.get('matched-at','?')[:50]}"
                        for f in critical[:5]
                    ])
                ) if critical else f"{len(s.nuclei_findings)} finding(s) — see report",
                "inline": False,
            })

        # Add AI summary if available
        if s.ai_summary:
            embed["fields"].append({
                "name": "🤖 AI Summary",
                "value": s.ai_summary[:900] + "..." if len(s.ai_summary) > 900 else s.ai_summary,
                "inline": False,
            })

        # Add SMB findings if any
        if s.smb_findings:
            smb_lines = []
            if s.smb_findings.get("anonymous_login"):
                smb_lines.append("⚠️ Anonymous login: **ALLOWED**")
            if s.smb_findings.get("shares"):
                smb_lines.append(f"Shares: {', '.join(s.smb_findings['shares'][:5])}")
            if s.smb_findings.get("users"):
                smb_lines.append(f"Users: {', '.join(s.smb_findings['users'][:5])}")
            if smb_lines:
                embed["fields"].append({
                    "name": "🖥️ SMB Findings",
                    "value": "\n".join(smb_lines),
                    "inline": False,
                })

        # Output path
        embed["fields"].append({
            "name": "📁 Output",
            "value": f"`{s.output_dir}`",
            "inline": False,
        })

        return {
            "username": "RVR Framework",
            "avatar_url": "https://i.imgur.com/4M34hi2.png",
            "embeds": [embed],
        }
