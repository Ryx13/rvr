"""
RVR — Discord Webhook Notifier v2
Sends a rich multi-embed engagement summary to Discord on scan completion,
mirroring the report structure: engagement overview, risk rating, severity-
ranked findings, attack surface, directory-services intel and AI next steps.

Findings come from the same FindingsBuilder the PDF/Markdown reports use, so
console, Discord and the written deliverables always agree on severity.

Discord constraints honoured throughout: field values capped at 1024 chars,
max 10 embeds, ISO-8601 timestamp with timezone.
"""

import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

import requests
from dotenv import load_dotenv

from rvr.utils.console import log_info, log_success, log_warn, log_error
from rvr.utils.state import RVRState
from rvr.output.findings import FindingsBuilder

load_dotenv()

# Same palette as the PDF report for brand consistency
RISK_COLORS = {
    "Critical": 0xC0392B,
    "High":     0xE67E22,
    "Medium":   0xD4AC0D,
    "Low":      0x1E8449,
    "Informational": 0x2E86C1,
    "Unknown":  0x7289DA,
}

SEV_EMOJI = {
    "Critical": "🔴",
    "High":     "🟠",
    "Medium":   "🟡",
    "Low":      "🟢",
    "Informational": "🔵",
}


class DiscordNotifier:
    def __init__(self, state: RVRState):
        self.state = state
        self.webhook_url = os.getenv("DISCORD_WEBHOOK_URL")
        self.builder = FindingsBuilder(state)
        self.findings: List[Any] = []
        self.risk = "Unknown"

    # ── public API ───────────────────────────────────────────────
    def send(self):
        if not self.webhook_url:
            log_warn("DISCORD_WEBHOOK_URL not set in .env — skipping notification")
            return

        log_info("Sending Discord notification...")
        self.findings = self.builder.build()
        self.risk = self.state.ai_risk_level or self.builder.overall_risk()

        payload = self._build_payload()

        try:
            resp = requests.post(self.webhook_url, json=payload, timeout=15)
            if resp.status_code in (200, 204):
                log_success("Discord notification sent")
            elif resp.status_code == 429:
                retry = resp.json().get("retry_after", 2) if resp.text else 2
                log_warn(f"Discord rate-limited — retry after {retry}s (notification dropped)")
            else:
                log_warn(f"Discord returned status {resp.status_code}: {resp.text[:200]}")
        except Exception as e:
            log_error(f"Discord notification failed: {e}")

    # ── payload assembly ─────────────────────────────────────────
    def _build_payload(self) -> Dict[str, Any]:
        embeds = [
            self._embed_engagement(),
            self._embed_findings(),
        ]
        attack_surface = self._embed_attack_surface()
        if attack_surface:
            embeds.append(attack_surface)
        ad_intel = self._embed_ad_intel()
        if ad_intel:
            embeds.append(ad_intel)
        ai = self._embed_ai()
        if ai:
            embeds.append(ai)

        return {
            "username": "RVR Framework",
            "avatar_url": "https://i.imgur.com/4M34hi2.png",
            "embeds": embeds,
        }

    # ── helpers ──────────────────────────────────────────────────
    @staticmethod
    def _clip(text: str, limit: int = 1024) -> str:
        """Truncate to Discord's field-value limit, on a line boundary."""
        text = str(text or "").strip()
        if len(text) <= limit:
            return text
        cut = text[:limit]
        nl = cut.rfind("\n")
        if nl > limit // 2:
            cut = cut[:nl]
        return cut + "…"

    def _duration(self) -> str:
        try:
            start = datetime.fromisoformat(self.state.start_time)
            end = datetime.fromisoformat(self.state.end_time or datetime.now().isoformat())
            secs = int((end - start).total_seconds())
            return f"{secs // 60}m {secs % 60}s"
        except Exception:
            return "N/A"

    def _sev_line(self) -> str:
        counts = self.builder.counts()
        parts = []
        for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
            n = counts.get(sev, 0)
            if n:
                parts.append(f"{SEV_EMOJI[sev]} {sev}: **{n}**")
        return "\n".join(parts) if parts else "No findings recorded"

    # ── embed 1: engagement overview ──────────────────────────────
    def _embed_engagement(self) -> Dict[str, Any]:
        s = self.state
        fields = [
            {
                "name": "📋 Engagement",
                "value": (
                    f"**Target:** `{s.target}` ({s.target_type})\n"
                    + (f"**Hostname:** `{s.hostname}`\n" if s.hostname else "")
                    + f"**Profile:** {s.profile}\n"
                    f"**Duration:** {self._duration()}\n"
                    f"**Attacker:** `{s.attacker_ip or 'N/A'}`"
                ),
                "inline": True,
            },
            {
                "name": "📊 Key Figures",
                "value": (
                    f"**Open ports:** {len(s.open_ports)}\n"
                    f"**Web paths:** {len(s.web_findings)}\n"
                    f"**Nuclei hits:** {len(s.nuclei_findings)}\n"
                    f"**Exploit matches:** {len(s.exploit_matches)}\n"
                    f"**Hashes captured:** {len(s.captured_hashes)}"
                ),
                "inline": True,
            },
            {
                "name": "🎯 Risk Rating",
                "value": f"**{self.risk.upper()}**",
                "inline": True,
            },
        ]
        if s.failed_modules:
            fields.append({
                "name": "⚠️ Failed Modules",
                "value": ", ".join(s.failed_modules[:10]),
                "inline": False,
            })
        fields.append({
            "name": "📁 Deliverables",
            "value": f"Report: `{s.output_dir / 'report.pdf'}`\nMarkdown: `{s.output_dir / 'report.md'}`\n"
                     f"Raw data: `{s.output_dir / 'raw_data.json'}`",
            "inline": False,
        })

        return {
            "title": f"🔍 RVR Scan Complete — {s.target}",
            "color": RISK_COLORS.get(self.risk, RISK_COLORS["Unknown"]),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "footer": {"text": f"RVR — Ryxvoid Recon Framework · {s.profile} profile · "
                               f"{len(s.completed_modules)} modules completed"},
            "fields": fields,
        }

    # ── embed 2: findings ────────────────────────────────────────
    def _embed_findings(self) -> Dict[str, Any]:
        top = [f for f in self.findings if f.severity in ("Critical", "High")][:8]
        fields = []

        fields.append({
            "name": f"📋 Findings — {len(self.findings)} total",
            "value": self._sev_line(),
            "inline": False,
        })

        if top:
            lines = [f"{SEV_EMOJI[f.severity]} **{f.fid}** — {f.title}" for f in top]
            more = len([f for f in self.findings if f.severity in ("Critical", "High")]) - len(top)
            if more > 0:
                lines.append(f"*…and {more} more critical/high — see report*")
            fields.append({
                "name": "🚨 Critical / High Detail",
                "value": self._clip("\n".join(lines)),
                "inline": False,
            })

        # Public exploit quick-list — the single most actionable signal
        if self.state.exploit_matches:
            seen, uniq = set(), []
            for m in self.state.exploit_matches:
                if m["id"] not in seen:
                    seen.add(m["id"])
                    uniq.append(m)
            lines = [f"`{m['id']}` {m['title'][:70]}" for m in uniq[:8]]
            if len(uniq) > 8:
                lines.append(f"*…and {len(uniq) - 8} more — Appendix E*")
            fields.append({
                "name": f"💥 Public Exploits — {len(uniq)} matched",
                "value": self._clip("\n".join(lines)),
                "inline": False,
            })

        return {
            "title": "🚩 Findings Summary",
            "color": RISK_COLORS.get(self.risk, RISK_COLORS["Unknown"]),
            "fields": fields,
        }

    # ── embed 3: attack surface ──────────────────────────────────
    def _embed_attack_surface(self) -> Optional[Dict[str, Any]]:
        s = self.state
        if not s.open_ports and not s.vhosts and not s.ssl_certs and not s.web_technologies:
            return None

        fields = []
        if s.open_ports:
            lines = [
                f"`{p['port']}/{p['proto']}` {p['service']}"
                + (f" — {(p.get('version') or '')[:40]}" if p.get("version") else "")
                for p in sorted(s.open_ports, key=lambda x: x["port"])[:15]
            ]
            if len(s.open_ports) > 15:
                lines.append(f"*…and {len(s.open_ports) - 15} more — Appendix A*")
            fields.append({
                "name": f"🔓 Open Ports ({len(s.open_ports)})",
                "value": self._clip("\n".join(lines)),
                "inline": False,
            })

        if s.web_technologies:
            clean = [t for t in s.web_technologies if t and "RESERVED" not in t and len(t) > 1]
            if clean:
                fields.append({
                    "name": "🛠 Web Stack",
                    "value": self._clip(", ".join(clean[:25]), 1024),
                    "inline": False,
                })

        if s.vhosts:
            lines = [f"`{v.get('host_full', v.get('host', '?'))}` ({v.get('status', '?')})"
                     for v in s.vhosts[:10]]
            if len(s.vhosts) > 10:
                lines.append(f"*…and {len(s.vhosts) - 10} more*")
            fields.append({
                "name": f"🌐 Virtual Hosts ({len(s.vhosts)})",
                "value": self._clip("\n".join(lines)),
                "inline": False,
            })

        if s.ssl_certs:
            lines = []
            for c in s.ssl_certs[:3]:
                san = ", ".join((c.get("san") or [])[:4])
                lines.append(f"`:{c.get('port', '?')}` CN `{c.get('cn', 'n/a')}`"
                             + (f" · SAN: {san}" if san else ""))
            fields.append({
                "name": "🔒 TLS Certificates",
                "value": self._clip("\n".join(lines)),
                "inline": False,
            })

        return {
            "title": "🗺 Attack Surface",
            "color": RISK_COLORS.get(self.risk, RISK_COLORS["Unknown"]),
            "fields": fields,
        }

    # ── embed 4: directory services intel ────────────────────────
    def _embed_ad_intel(self) -> Optional[Dict[str, Any]]:
        s = self.state
        smb, ldap, krb = s.smb_findings, s.ldap_findings, s.kerberos_findings
        bh, adcs, rdp = s.bloodhound_findings, s.adcs_findings, s.rdp_findings
        hashes = s.captured_hashes

        if not (smb or ldap or krb or bh or adcs or rdp or hashes):
            return None

        fields = []
        lines = []

        if s.get_domain():
            lines.append(f"🌐 **Domain:** `{s.get_domain()}`")
        if smb.get("signing") == "disabled":
            lines.append("⚠️ SMB signing **disabled** (relay risk)")
        if smb.get("anonymous_login"):
            lines.append(f"🔓 SMB anonymous sessions **allowed** — shares: "
                         f"{', '.join((smb.get('shares') or [])[:5]) or 'n/a'}")
        if smb.get("spray_hits"):
            lines.append(f"🔑 **Valid credentials:** {'; '.join(smb['spray_hits'][:3])}")

        if ldap.get("anonymous_bind"):
            n = len(ldap.get("anonymous_users") or [])
            lines.append(f"🔓 LDAP anonymous bind **allowed**"
                         + (f" — {n} accounts enumerable" if n else ""))

        if krb.get("asrep_roast", {}).get("count"):
            asrep = krb["asrep_roast"]
            lines.append(f"🔴 **AS-REP roastable ({asrep['count']}):** "
                         f"{', '.join(asrep.get('accounts', [])[:6])}")
        if krb.get("kerberoast", {}).get("count"):
            kerb = krb["kerberoast"]
            lines.append(f"🟠 **Kerberoastable ({kerb['count']}):** "
                         f"{', '.join(kerb.get('accounts', [])[:6])}")

        if hashes:
            lines.append(f"🗝 **{len(hashes)} crackable hash(es) captured** — "
                         f"crack commands in `{s.output_dir / 'kerberos'}`")

        if bh.get("zip_path"):
            lines.append(f"hound **BloodHound data collected** ({bh.get('mode')}) — `{bh['zip_path']}`")
        elif bh.get("manual_commands"):
            lines.append("hound BloodHound deferred — manual commands written")

        if adcs.get("web_enrollment"):
            lines.append(f"📜 ADCS web enrollment: `{adcs['web_enrollment'].get('url', '')}`")
        if adcs.get("vulnerable_templates"):
            escs = " ".join(adcs["vulnerable_templates"].get("esc_classes", []))
            lines.append(f"🔴 **Vulnerable cert templates:** {escs}")

        if rdp.get("nla_enabled") is False:
            lines.append("⚠️ RDP **NLA not enforced**")

        if lines:
            fields.append({
                "name": "🛡 Directory Services & Attack Intel",
                "value": self._clip("\n".join(lines)),
                "inline": False,
            })

        users = s.get_ad_users()
        if users:
            fields.append({
                "name": f"👥 Enumerated Accounts ({len(users)})",
                "value": self._clip(", ".join(f"`{u}`" for u in users[:40])),
                "inline": False,
            })

        if not fields:
            return None

        return {
            "title": "🏰 AD / Attack Intel",
            "color": RISK_COLORS.get(self.risk, RISK_COLORS["Unknown"]),
            "fields": fields,
        }

    # ── embed 5: AI analysis ─────────────────────────────────────
    def _embed_ai(self) -> Optional[Dict[str, Any]]:
        s = self.state
        if not (s.ai_summary or s.ai_attack_paths or s.ai_next_steps):
            return None

        fields = []
        if s.ai_summary:
            fields.append({
                "name": "🤖 AI Assessment" + (f" ({s.ai_provider_used})" if s.ai_provider_used else ""),
                "value": self._clip(s.ai_summary, 1024),
                "inline": False,
            })

        if s.ai_attack_paths:
            lines = []
            for i, p in enumerate(s.ai_attack_paths[:3], start=1):
                line = f"**{i}. {p.get('name', 'unnamed')}**"
                if p.get("mitre"):
                    line += f" · {p['mitre']}"
                lines.append(line)
            fields.append({
                "name": f"🗺 Attack Paths ({len(s.ai_attack_paths)})",
                "value": self._clip("\n".join(lines)),
                "inline": False,
            })

        if s.ai_next_steps:
            lines = [f"**{i}.** {step}" for i, step in enumerate(s.ai_next_steps[:5], start=1)]
            fields.append({
                "name": "▶️ Next Steps",
                "value": self._clip("\n".join(lines)),
                "inline": False,
            })

        if s.ai_risk_justification:
            fields.append({
                "name": "🎯 Risk Rationale",
                "value": self._clip(s.ai_risk_justification, 600),
                "inline": False,
            })

        return {
            "title": "🧠 AI Analysis",
            "color": RISK_COLORS.get(self.risk, RISK_COLORS["Unknown"]),
            "footer": {"text": "AI output is analytical guidance — validate before acting"},
            "fields": fields,
        }
