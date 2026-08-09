"""
RVR — PDF Report v2
Comprehensive, shows all findings properly
"""

import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

from rvr.utils.console import log_info, log_success, log_warn, log_error
from rvr.utils.state import RVRState

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm, cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, KeepTogether, Image
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False

C_BLACK      = colors.HexColor("#0A0A0A")
C_DARK       = colors.HexColor("#1A1A2E")
C_BLUE       = colors.HexColor("#1B4F72")
C_BLUE_LIGHT = colors.HexColor("#2E86C1")
C_RED        = colors.HexColor("#C0392B")
C_ORANGE     = colors.HexColor("#E67E22")
C_YELLOW     = colors.HexColor("#D4AC0D")
C_GREEN      = colors.HexColor("#1E8449")
C_GREY_DARK  = colors.HexColor("#2C3E50")
C_GREY_LIGHT = colors.HexColor("#EBF5FB")
C_WHITE      = colors.white
C_ROW_ALT    = colors.HexColor("#F8FBFD")
C_ROW_GREEN  = colors.HexColor("#EAFAF1")
C_ROW_RED    = colors.HexColor("#FDEDEC")
C_ROW_YELLOW = colors.HexColor("#FEF9E7")


class PDFReport:
    def __init__(self, state: RVRState):
        self.state = state
        self.output_path = state.output_dir / "report.pdf"

    def _escape(self, text: str) -> str:
        return (str(text).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;'))

    def generate(self):
        if not REPORTLAB_OK:
            log_error("ReportLab not installed")
            return

        log_info("Generating PDF report...")

        doc = SimpleDocTemplate(
            str(self.output_path),
            pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=2.5*cm, bottomMargin=2*cm,
            title=f"RVR — {self.state.target}",
            author="RVR Ryxvoid Recon Framework",
        )

        styles = self._styles()
        story = []

        story += self._cover(styles)
        story.append(PageBreak())
        story += self._executive_summary(styles)
        story += self._metadata(styles)

        if self.state.open_ports:
            story += self._network(styles)

        if self.state.web_findings or self.state.web_technologies:
            story += self._web(styles)

        if self.state.screenshots:
            story += self._screenshots(styles)

        if self.state.nuclei_findings:
            story += self._vulns(styles)

        if self.state.ftp_findings:
            story += self._ftp(styles)

        if self.state.database_findings:
            story += self._databases(styles)

        if self.state.ldap_findings:
            story += self._ldap(styles)

        if self.state.rdp_findings:
            story += self._rdp(styles)

        if self.state.smb_findings:
            story += self._smb(styles)

        if self.state.nfs_mounts:
            story += self._nfs(styles)

        if self.state.snmp_data:
            story += self._snmp(styles)

        if self.state.subdomains or self.state.emails:
            story += self._osint(styles)

        if self.state.ai_summary:
            story += self._ai_section(styles)

        story += self._artifacts(styles)

        doc.build(story, onFirstPage=self._hf, onLaterPages=self._hf)
        log_success(f"Report saved: {self.output_path}")

    def _hf(self, canvas, doc):
        canvas.saveState()
        w, h = A4
        canvas.setFillColor(C_DARK)
        canvas.rect(0, h - 1.2*cm, w, 1.2*cm, fill=1, stroke=0)
        canvas.setFillColor(C_WHITE)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawString(2*cm, h - 0.8*cm, "RVR — RYXVOID RECON FRAMEWORK")
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(w - 2*cm, h - 0.8*cm, f"CONFIDENTIAL — {self.state.target}")
        canvas.setFillColor(C_GREY_DARK)
        canvas.rect(0, 0, w, 0.9*cm, fill=1, stroke=0)
        canvas.setFillColor(C_WHITE)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(2*cm, 0.3*cm, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        canvas.drawCentredString(w/2, 0.3*cm, "CONFIDENTIAL — AUTHORISED USE ONLY")
        canvas.drawRightString(w - 2*cm, 0.3*cm, f"Page {doc.page}")
        canvas.restoreState()

    def _styles(self):
        s = {}
        s["h1"] = ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=13,
            textColor=C_WHITE, backColor=C_DARK, spaceAfter=10, spaceBefore=14,
            leftIndent=6, rightIndent=6, borderPad=6)
        s["h2"] = ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=10,
            textColor=C_BLUE, spaceAfter=6, spaceBefore=8)
        s["body"] = ParagraphStyle("body", fontName="Helvetica", fontSize=9,
            textColor=C_BLACK, spaceAfter=4, leading=14)
        s["body_bold"] = ParagraphStyle("body_bold", fontName="Helvetica-Bold",
            fontSize=9, textColor=C_DARK, spaceAfter=4)
        s["code"] = ParagraphStyle("code", fontName="Courier", fontSize=8,
            textColor=C_DARK, backColor=C_GREY_LIGHT, spaceAfter=4,
            leftIndent=8, rightIndent=8, borderPad=4)
        s["label"] = ParagraphStyle("label", fontName="Helvetica-Bold", fontSize=8,
            textColor=colors.HexColor("#5D6D7E"), spaceAfter=2)
        s["cover_title"] = ParagraphStyle("cover_title", fontName="Helvetica-Bold",
            fontSize=32, textColor=C_WHITE, spaceAfter=8)
        s["cover_sub"] = ParagraphStyle("cover_sub", fontName="Helvetica",
            fontSize=14, textColor=colors.HexColor("#AED6F1"), spaceAfter=4)
        s["finding_critical"] = ParagraphStyle("finding_critical", fontName="Helvetica-Bold",
            fontSize=9, textColor=C_RED)
        s["finding_high"] = ParagraphStyle("finding_high", fontName="Helvetica-Bold",
            fontSize=9, textColor=C_ORANGE)
        return s

    def _tbl(self, data, col_widths, header=True):
        """Standard styled table"""
        t = Table(data, colWidths=col_widths)
        style = [
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#D5D8DC")),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_ROW_ALT]),
        ]
        if header:
            style += [
                ("BACKGROUND",  (0, 0), (-1, 0), C_BLUE),
                ("TEXTCOLOR",   (0, 0), (-1, 0), C_WHITE),
                ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ]
        t.setStyle(TableStyle(style))
        return t

    def _cover(self, styles):
        story = [Spacer(1, 1*cm)]
        title_t = Table([[Paragraph("RVR", styles["cover_title"])]],
                        colWidths=[17*cm])
        title_t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), C_DARK),
            ("TOPPADDING", (0,0), (-1,-1), 18),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("LEFTPADDING", (0,0), (-1,-1), 14),
        ]))
        story.append(title_t)

        sub_t = Table([[Paragraph("Ryxvoid Recon Framework", styles["cover_sub"])]],
                      colWidths=[17*cm])
        sub_t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), C_BLUE),
            ("TOPPADDING", (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 12),
            ("LEFTPADDING", (0,0), (-1,-1), 14),
        ]))
        story.append(sub_t)
        story.append(Spacer(1, 1.2*cm))

        s = self.state
        risk = s.ai_risk_level or "Unknown"

        rows = [
            ["TARGET",          s.target],
            ["TARGET TYPE",     s.target_type.upper()],
            ["SCAN PROFILE",    s.profile.upper()],
            ["ATTACKER IP",     f"{s.attacker_ip or 'N/A'} ({s.attacker_iface or 'N/A'})"],
            ["RISK LEVEL",      risk],
            ["OPEN PORTS",      str(len(s.open_ports))],
            ["WEB FINDINGS",    str(len(s.web_findings))],
            ["VULNERABILITIES", str(len(s.nuclei_findings))],
            ["NFS MOUNTS",      str(len(s.nfs_mounts))],
            ["DATE",            datetime.now().strftime("%Y-%m-%d")],
            ["OPERATOR",        "ryx13"],
        ]

        detail_t = Table(
            [[Paragraph(k, styles["label"]), Paragraph(str(v), styles["body_bold"])]
             for k, v in rows],
            colWidths=[5*cm, 12*cm]
        )
        detail_t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (0, -1), C_GREY_LIGHT),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#D5D8DC")),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ]))
        story.append(detail_t)
        story.append(Spacer(1, 1.5*cm))

        notice_t = Table([[Paragraph(
            "⚠ CONFIDENTIAL — This document contains sensitive security assessment data. "
            "Distribution is restricted to authorised personnel only.",
            styles["body"]
        )]], colWidths=[17*cm])
        notice_t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), C_ROW_RED),
            ("BOX",           (0,0), (-1,-1), 1, C_RED),
            ("LEFTPADDING",   (0,0), (-1,-1), 10),
            ("TOPPADDING",    (0,0), (-1,-1), 8),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ]))
        story.append(notice_t)
        return story

    def _executive_summary(self, styles):
        story = [Paragraph("Executive Summary", styles["h1"])]

        if self.state.ai_summary:
            story.append(Paragraph(self.state.ai_summary, styles["body"]))
        else:
            parts = [f"Automated reconnaissance against {self._escape(self.state.target)} using the {self.state.profile} profile."]
            if self.state.open_ports:
                parts.append(f"{len(self.state.open_ports)} open ports identified.")
            if self.state.web_findings:
                interesting = [f for f in self.state.web_findings if f["status"] in [200, 201]]
                parts.append(f"{len(self.state.web_findings)} web paths enumerated ({len(interesting)} accessible).")
            if self.state.nuclei_findings:
                parts.append(f"{len(self.state.nuclei_findings)} vulnerability findings from Nuclei.")
            if self.state.nfs_mounts:
                parts.append(f"{len(self.state.nfs_mounts)} NFS mount(s) exposed.")
            story.append(Paragraph(" ".join(parts), styles["body"]))

        if self.state.ai_vectors:
            story.append(Spacer(1, 0.3*cm))
            story.append(Paragraph("Identified Attack Vectors", styles["body_bold"]))
            for v in self.state.ai_vectors:
                story.append(Paragraph(f"• {v}", styles["body"]))

        story.append(Spacer(1, 0.4*cm))
        return story

    def _metadata(self, styles):
        story = [Paragraph("Scan Metadata", styles["h1"])]
        s = self.state
        elapsed = "N/A"
        try:
            start = datetime.fromisoformat(s.start_time)
            end = datetime.fromisoformat(s.end_time or datetime.now().isoformat())
            elapsed = str(end - start).split(".")[0]
        except Exception:
            pass

        rows = [
            ["Parameter", "Value"],
            ["Target", s.target],
            ["Profile", s.profile],
            ["Attacker IP", f"{s.attacker_ip or 'N/A'} ({s.attacker_iface or 'N/A'})"],
            ["Start Time", s.start_time[:19]],
            ["Duration", elapsed],
            ["Modules Completed", ", ".join(s.completed_modules) or "None"],
            ["Modules Failed", ", ".join(s.failed_modules) or "None"],
        ]
        story.append(self._tbl(rows, [5*cm, 12*cm]))
        story.append(Spacer(1, 0.4*cm))
        return story

    def _network(self, styles):
        story = [Paragraph("Network Findings", styles["h1"])]
        story.append(Paragraph(
            f"{len(self.state.open_ports)} open port(s) identified on {self.state.target}.",
            styles["body"]
        ))

        rows = [["Port", "Protocol", "Service", "Version / Banner"]]
        for p in sorted(self.state.open_ports, key=lambda x: x["port"]):
            rows.append([
                str(p["port"]),
                p["proto"].upper(),
                p["service"],
                self._escape(p.get('version', ''))[:65],
            ])
        story.append(self._tbl(rows, [2*cm, 2.5*cm, 3*cm, 9.5*cm]))

        # Nmap script output
        scripts_found = [(p["port"], p["service"], sid, out)
                         for p in self.state.open_ports
                         for sid, out in p.get("scripts", {}).items()
                         if out.strip()]
        if scripts_found:
            story.append(Spacer(1, 0.3*cm))
            story.append(Paragraph("Nmap Script Output", styles["h2"]))
            for port, svc, script_id, output in scripts_found[:20]:
                story.append(Paragraph(
                    f"<b>{port}/{svc} — {script_id}</b>",
                    styles["body_bold"]
                ))
                # Truncate long outputs
                out_text = self._escape(output.strip())[:500]
                story.append(Paragraph(out_text.replace("\n", "<br/>"), styles["code"]))

        story.append(Spacer(1, 0.4*cm))
        return story

    def _web(self, styles):
        story = [Paragraph("Web Enumeration", styles["h1"])]

        if self.state.web_technologies:
            clean_techs = [t for t in self.state.web_technologies
                           if t and "RESERVED" not in t and len(t) > 1]
            if clean_techs:
                story.append(Paragraph(
                    f"<b>Detected technologies:</b> {', '.join(clean_techs)}",
                    styles["body"]
                ))

        findings = self.state.web_findings
        if not findings:
            story.append(Paragraph("No web findings.", styles["body"]))
            story.append(Spacer(1, 0.4*cm))
            return story

        # Categorise
        accessible = [f for f in findings if f["status"] in [200, 201, 204]]
        forbidden  = [f for f in findings if f["status"] in [401, 403]]
        redirects  = [f for f in findings if f["status"] in [301, 302, 307]]
        errors     = [f for f in findings if f["status"] >= 500]

        story.append(Paragraph(
            f"Total findings: {len(findings)} — "
            f"Accessible: {len(accessible)} — "
            f"Forbidden: {len(forbidden)} — "
            f"Redirects: {len(redirects)} — "
            f"Errors: {len(errors)}",
            styles["body"]
        ))
        story.append(Spacer(1, 0.2*cm))

        def findings_table(title, rows_data, row_color):
            if not rows_data:
                return []
            s2 = [Paragraph(title, styles["h2"])]
            rows = [["Status", "URL", "Size", "Source"]]
            for f in rows_data[:100]:
                rows.append([
                    str(f["status"]),
                    f["url"][:75],
                    str(f.get("size", "")),
                    f.get("source", "ffuf"),
                ])
            t = Table(rows, colWidths=[1.8*cm, 11*cm, 1.5*cm, 2.2*cm])
            style_list = [
                ("BACKGROUND",    (0, 0), (-1, 0), C_BLUE),
                ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
                ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 7),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, row_color]),
                ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#D5D8DC")),
                ("TOPPADDING",    (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING",   (0, 0), (-1, -1), 4),
            ]
            t.setStyle(TableStyle(style_list))
            s2.append(t)
            if len(rows_data) > 100:
                s2.append(Paragraph(
                    f"... and {len(rows_data)-100} more — see raw ffuf output.",
                    styles["body"]
                ))
            return s2

        story += findings_table(f"Accessible Paths (2xx) — {len(accessible)}", accessible, C_ROW_GREEN)
        story += findings_table(f"Authentication Required (4xx) — {len(forbidden)}", forbidden, C_ROW_YELLOW)
        story += findings_table(f"Redirects (3xx) — {len(redirects)}", redirects[:30], C_ROW_ALT)
        story += findings_table(f"Server Errors (5xx) — {len(errors)}", errors, C_ROW_RED)

        story.append(Spacer(1, 0.4*cm))
        return story

    def _vulns(self, styles):
        story = [Paragraph("Vulnerability Findings (Nuclei)", styles["h1"])]
        story.append(Paragraph(
            f"{len(self.state.nuclei_findings)} finding(s) identified by Nuclei scanner.",
            styles["body"]
        ))

        rows = [["Severity", "Template ID", "Name", "Matched At"]]
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            self.state.nuclei_findings,
            key=lambda x: sev_order.get(x.get("info", {}).get("severity", "info").lower(), 5)
        )

        for f in sorted_findings[:50]:
            info = f.get("info", {})
            sev = info.get("severity", "unknown")
            rows.append([
                sev.upper(),
                f.get("template-id", "N/A")[:25],
                info.get("name", "N/A")[:35],
                f.get("matched-at", "N/A")[:50],
            ])

        t = Table(rows, colWidths=[2.2*cm, 4.5*cm, 5.5*cm, 5.3*cm])
        sev_colors_map = {
            "CRITICAL": C_RED, "HIGH": C_ORANGE,
            "MEDIUM": C_YELLOW, "LOW": C_GREEN,
        }

        style_list = [
            ("BACKGROUND",    (0, 0), (-1, 0), C_BLUE),
            ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_ROW_ALT]),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#D5D8DC")),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ]
        t.setStyle(TableStyle(style_list))
        story.append(t)
        story.append(Spacer(1, 0.4*cm))
        return story

    def _smb(self, styles):
        story = [Paragraph("SMB / Active Directory", styles["h1"])]
        smb = self.state.smb_findings

        rows = [["Property", "Value"]]
        for key in ["signing", "anonymous_login", "os", "domain"]:
            if key in smb:
                val = smb[key]
                if isinstance(val, dict):
                    val = json.dumps(val)[:80]
                rows.append([key.replace("_", " ").title(), str(val)])

        if len(rows) > 1:
            story.append(self._tbl(rows, [5*cm, 12*cm]))
            story.append(Spacer(1, 0.2*cm))

        if smb.get("shares"):
            story.append(Paragraph("Shares", styles["h2"]))
            share_rows = [["Share Name"]] + [[s] for s in smb["shares"]]
            story.append(self._tbl(share_rows, [17*cm]))
            story.append(Spacer(1, 0.2*cm))

        if smb.get("users"):
            story.append(Paragraph("Users (via RID/enum4linux)", styles["h2"]))
            user_rows = [["Username"]] + [[u] for u in smb["users"][:50]]
            story.append(self._tbl(user_rows, [17*cm]))

        story.append(Spacer(1, 0.4*cm))
        return story

    def _nfs(self, styles):
        story = [Paragraph("NFS Enumeration", styles["h1"])]
        story.append(Paragraph(
            f"{len(self.state.nfs_mounts)} NFS mount(s) exposed on {self.state.target}.",
            styles["body"]
        ))
        rows = [["Mount Point"]] + [[m] for m in self.state.nfs_mounts]
        story.append(self._tbl(rows, [17*cm]))
        story.append(Spacer(1, 0.4*cm))
        return story

    def _snmp(self, styles):
        story = [Paragraph("SNMP Enumeration", styles["h1"])]
        d = self.state.snmp_data
        rows = [["Property", "Value"]]
        for key in ["community", "system", "hostname", "contact", "location"]:
            if key in d:
                rows.append([key.title(), str(d[key])[:80]])
        if len(rows) > 1:
            story.append(self._tbl(rows, [5*cm, 12*cm]))
        story.append(Spacer(1, 0.4*cm))
        return story

    def _ftp(self, styles):
        story = [Paragraph("FTP Enumeration", styles["h1"])]
        f = self.state.ftp_findings

        rows = [["Property", "Value"]]
        if f.get("banner"):
            rows.append(["Banner", self._escape(f["banner"])[:100]])
        anon = f.get("anonymous_login")
        rows.append(["Anonymous Login", "ALLOWED" if anon else "DENIED"])
        story.append(self._tbl(rows, [5*cm, 12*cm]))

        if f.get("anon_listing"):
            story.append(Spacer(1, 0.2*cm))
            story.append(Paragraph(
                f"Directory listing visible via anonymous FTP ({len(f['anon_listing'])} item(s)):",
                styles["h2"]
            ))
            listing_rows = [["Path"]] + [[self._escape(p)] for p in f["anon_listing"][:50]]
            story.append(self._tbl(listing_rows, [17*cm]))

        story.append(Spacer(1, 0.4*cm))
        return story

    def _databases(self, styles):
        story = [Paragraph("Database Enumeration", styles["h1"])]
        rows = [["Service", "Port", "Status"]]
        for name, finding in self.state.database_findings.items():
            flagged = finding.get("empty_password") or finding.get("unauthenticated")
            status = finding.get("note") or ("MISCONFIGURED / UNAUTHENTICATED" if flagged else "Detected — no misconfig found")
            rows.append([name, str(finding.get("port", "")), self._escape(status)[:70]])
        story.append(self._tbl(rows, [4*cm, 2*cm, 11*cm]))
        story.append(Spacer(1, 0.4*cm))
        return story

    def _ldap(self, styles):
        story = [Paragraph("LDAP / Active Directory", styles["h1"])]
        d = self.state.ldap_findings

        rows = [["Property", "Value"]]
        if "anonymous_bind" in d:
            rows.append(["Anonymous Bind", "ALLOWED" if d["anonymous_bind"] else "DENIED"])
        for key in ["domain", "default_naming_context"]:
            if d.get(key):
                rows.append([key.replace("_", " ").title(), self._escape(str(d[key]))[:80]])
        if len(rows) > 1:
            story.append(self._tbl(rows, [5*cm, 12*cm]))

        if d.get("anonymous_users"):
            story.append(Spacer(1, 0.2*cm))
            story.append(Paragraph(
                f"Accounts enumerable via anonymous bind ({len(d['anonymous_users'])}):",
                styles["h2"]
            ))
            user_rows = [["Account"]] + [[self._escape(u)] for u in d["anonymous_users"][:50]]
            story.append(self._tbl(user_rows, [17*cm]))

        story.append(Spacer(1, 0.4*cm))
        return story

    def _rdp(self, styles):
        story = [Paragraph("RDP Enumeration", styles["h1"])]
        d = self.state.rdp_findings

        rows = [["Property", "Value"]]
        for key, label in [
            ("dns_computer", "Hostname (DNS)"), ("netbios_computer", "Hostname (NetBIOS)"),
            ("dns_domain", "Domain (DNS)"), ("netbios_domain", "Domain (NetBIOS)"),
            ("os_build", "OS Build"),
        ]:
            if d.get(key):
                rows.append([label, self._escape(str(d[key]))[:80]])
        if "nla_enabled" in d:
            rows.append(["NLA Enforced", "Yes" if d["nla_enabled"] else "No"])
        if d.get("security_protocols"):
            rows.append(["Security Protocols", ", ".join(d["security_protocols"])])

        if len(rows) > 1:
            story.append(self._tbl(rows, [5*cm, 12*cm]))
        story.append(Spacer(1, 0.4*cm))
        return story

    def _screenshots(self, styles):
        story = [Paragraph("Web Screenshots", styles["h1"])]
        story.append(Paragraph(
            f"{len(self.state.screenshots)} screenshot(s) captured.",
            styles["body"]
        ))
        story.append(Spacer(1, 0.2*cm))

        max_width = 16 * cm
        for shot in self.state.screenshots:
            path = shot.get("path")
            url = shot.get("url", "")
            if not path or not Path(path).exists():
                continue
            try:
                img = Image(path)
                if img.imageWidth > 0:
                    scale = min(max_width / img.imageWidth, 1.0)
                    img.drawWidth = img.imageWidth * scale
                    img.drawHeight = img.imageHeight * scale
                story.append(Paragraph(self._escape(url), styles["body_bold"]))
                story.append(img)
                story.append(Spacer(1, 0.4*cm))
            except Exception as e:
                log_warn(f"Could not embed screenshot {path}: {e}")

        return story

    def _osint(self, styles):
        story = [Paragraph("OSINT — Passive Reconnaissance", styles["h1"])]

        if self.state.subdomains:
            story.append(Paragraph(f"{len(self.state.subdomains)} subdomains discovered:", styles["h2"]))
            rows = [["Subdomain"]] + [[s] for s in self.state.subdomains[:100]]
            story.append(self._tbl(rows, [17*cm]))
            story.append(Spacer(1, 0.2*cm))

        if self.state.emails:
            story.append(Paragraph(f"{len(self.state.emails)} email addresses found:", styles["h2"]))
            rows = [["Email"]] + [[e] for e in self.state.emails[:50]]
            story.append(self._tbl(rows, [17*cm]))

        story.append(Spacer(1, 0.4*cm))
        return story

    def _ai_section(self, styles):
        provider_label = (self.state.ai_provider_used or "AI").title()
        story = [Paragraph(f"AI-Assisted Analysis ({provider_label})", styles["h1"])]
        story.append(Paragraph(self.state.ai_summary, styles["body"]))

        if self.state.ai_cves:
            story.append(Spacer(1, 0.2*cm))
            story.append(Paragraph("Probable CVEs", styles["h2"]))
            for cve in self.state.ai_cves:
                story.append(Paragraph(f"• {cve}", styles["body"]))

        if self.state.ai_vectors:
            story.append(Spacer(1, 0.2*cm))
            story.append(Paragraph("Attack Vectors", styles["h2"]))
            for v in self.state.ai_vectors:
                story.append(Paragraph(f"• {v}", styles["body"]))

        if self.state.ai_priority_targets:
            story.append(Spacer(1, 0.2*cm))
            story.append(Paragraph("Priority Targets", styles["h2"]))
            for t in self.state.ai_priority_targets:
                story.append(Paragraph(f"• {t}", styles["body"]))

        if self.state.ai_manual_validation:
            story.append(Spacer(1, 0.2*cm))
            story.append(Paragraph("Recommended Manual Validation", styles["h2"]))
            for cmd in self.state.ai_manual_validation:
                story.append(Paragraph(self._escape(cmd), styles["code"]))

        story.append(Spacer(1, 0.4*cm))
        return story

    def _artifacts(self, styles):
        story = [Paragraph("Appendix — Output Artifacts", styles["h1"])]
        story.append(Paragraph(str(self.state.output_dir), styles["code"]))
        story.append(Spacer(1, 0.3*cm))

        if self.state.artifacts:
            rows = [["Artifact", "Path"]]
            for key, path in self.state.artifacts.items():
                rows.append([key, str(path)])
            story.append(self._tbl(rows, [4.5*cm, 12.5*cm]))

        return story


def _escape(text: str) -> str:
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))