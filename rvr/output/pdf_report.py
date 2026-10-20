"""
RVR — PDF Report v3 (commercial-grade)
Renders the engagement deliverable expected from a professional assessment:
cover, engagement overview, executive summary, risk matrix, detailed
findings (with evidence, impact and remediation), attack-path analysis, a
prioritised remediation roadmap, and full technical appendices.

Findings come from rvr.output.findings.FindingsBuilder — deterministic
detections merged with AI analysis — so the report is complete with or
without an AI provider configured.
"""

import json
from pathlib import Path
from datetime import datetime

from rvr.utils.console import log_info, log_success, log_warn, log_error
from rvr.utils.state import RVRState
from rvr.output.findings import FindingsBuilder, SEVERITY_ORDER

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, Image, KeepTogether,
    )
    from reportlab.platypus.tableofcontents import TableOfContents
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False

C_BLACK      = colors.HexColor("#0A0A0A")
C_DARK       = colors.HexColor("#12122B")
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
C_ROW_ORANGE = colors.HexColor("#FDF2E9")

SEV_COLORS = {
    "Critical": C_RED, "High": C_ORANGE, "Medium": C_YELLOW,
    "Low": C_GREEN, "Informational": C_BLUE_LIGHT,
}
SEV_ROW_BG = {
    "Critical": C_ROW_RED, "High": C_ROW_ORANGE, "Medium": C_ROW_YELLOW,
    "Low": C_ROW_GREEN, "Informational": C_ROW_ALT,
}


class _TOCDoc(SimpleDocTemplate):
    """SimpleDocTemplate that records h1/h2 headings for the TOC."""
    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph):
            style = flowable.style.name
            if style in ("h1", "h2"):
                level = 0 if style == "h1" else 1
                text = flowable.getPlainText()
                self.notify("TOCEntry", (level, text, self.page))


class PDFReport:
    def __init__(self, state: RVRState):
        self.state = state
        self.output_path = state.output_dir / "report.pdf"
        self.builder = FindingsBuilder(state)
        self.findings = []
        self.risk = "Informational"

    def _esc(self, text) -> str:
        return (str(text).replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))

    # ── Main ─────────────────────────────────────────────────────
    def generate(self):
        if not REPORTLAB_OK:
            log_error("ReportLab not installed — skipping PDF report")
            return

        log_info("Generating PDF engagement report...")
        self.findings = self.builder.build()
        self.risk = self.state.ai_risk_level or self.builder.overall_risk()

        doc = _TOCDoc(
            str(self.output_path),
            pagesize=A4,
            leftMargin=2 * cm, rightMargin=2 * cm,
            topMargin=2.5 * cm, bottomMargin=2 * cm,
            title=f"RVR Penetration Assessment — {self.state.target}",
            author="RVR — Ryxvoid Recon Framework",
        )

        styles = self._styles()
        story = []

        story += self._cover(styles)
        story.append(PageBreak())
        story += self._toc(styles)
        story.append(PageBreak())
        story += self._engagement_overview(styles)
        story += self._executive_summary(styles)
        story += self._risk_summary(styles)
        story.append(PageBreak())
        story += self._detailed_findings(styles)
        story += self._attack_paths(styles)
        story += self._remediation_roadmap(styles)
        story.append(PageBreak())
        story += self._appendix_network(styles)
        story += self._appendix_web(styles)
        story += self._appendix_ad(styles)
        story += self._appendix_hashes(styles)
        story += self._appendix_exploits(styles)
        story += self._appendix_osint(styles)
        story += self._appendix_screenshots(styles)
        story += self._appendix_artifacts(styles)

        doc.multiBuild(story, onFirstPage=self._hf, onLaterPages=self._hf)
        log_success(f"Report saved: {self.output_path}")

    # ── Page furniture ───────────────────────────────────────────
    def _hf(self, canvas, doc):
        canvas.saveState()
        w, h = A4
        canvas.setFillColor(C_DARK)
        canvas.rect(0, h - 1.2 * cm, w, 1.2 * cm, fill=1, stroke=0)
        canvas.setFillColor(C_WHITE)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawString(2 * cm, h - 0.8 * cm, "RVR — RYXVOID RECON FRAMEWORK")
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(w - 2 * cm, h - 0.8 * cm, f"CONFIDENTIAL — {self.state.target}")
        canvas.setFillColor(C_GREY_DARK)
        canvas.rect(0, 0, w, 0.9 * cm, fill=1, stroke=0)
        canvas.setFillColor(C_WHITE)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(2 * cm, 0.3 * cm, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        canvas.drawCentredString(w / 2, 0.3 * cm, "CONFIDENTIAL — AUTHORISED USE ONLY")
        canvas.drawRightString(w - 2 * cm, 0.3 * cm, f"Page {doc.page}")
        canvas.restoreState()

    def _styles(self):
        s = {}
        s["h1"] = ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=13,
                                 textColor=C_WHITE, backColor=C_DARK, spaceAfter=10, spaceBefore=14,
                                 leftIndent=6, rightIndent=6, borderPad=6)
        s["h2"] = ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=10.5,
                                 textColor=C_BLUE, spaceAfter=6, spaceBefore=10)
        s["h3"] = ParagraphStyle("h3", fontName="Helvetica-Bold", fontSize=9.5,
                                 textColor=C_GREY_DARK, spaceAfter=4, spaceBefore=8)
        s["body"] = ParagraphStyle("body", fontName="Helvetica", fontSize=9,
                                   textColor=C_BLACK, spaceAfter=4, leading=13.5)
        s["body_bold"] = ParagraphStyle("body_bold", fontName="Helvetica-Bold",
                                        fontSize=9, textColor=C_DARK, spaceAfter=4)
        s["code"] = ParagraphStyle("code", fontName="Courier", fontSize=7.5,
                                   textColor=C_DARK, backColor=C_GREY_LIGHT, spaceAfter=4,
                                   leading=10, leftIndent=8, rightIndent=8, borderPad=4)
        s["label"] = ParagraphStyle("label", fontName="Helvetica-Bold", fontSize=8,
                                    textColor=colors.HexColor("#5D6D7E"), spaceAfter=2)
        s["cover_title"] = ParagraphStyle("cover_title", fontName="Helvetica-Bold",
                                          fontSize=30, textColor=C_WHITE, spaceAfter=8, leading=34)
        s["cover_sub"] = ParagraphStyle("cover_sub", fontName="Helvetica",
                                        fontSize=13, textColor=colors.HexColor("#AED6F1"), spaceAfter=4, leading=17)
        s["toc_h"] = ParagraphStyle("toc_h", fontName="Helvetica-Bold", fontSize=13,
                                    textColor=C_WHITE, backColor=C_DARK, spaceAfter=10, spaceBefore=4,
                                    leftIndent=6, rightIndent=6, borderPad=6)
        s["quote"] = ParagraphStyle("quote", fontName="Helvetica-Oblique", fontSize=9,
                                    textColor=C_GREY_DARK, leftIndent=10, rightIndent=10,
                                    spaceAfter=6, spaceBefore=2)
        return s

    def _tbl(self, data, col_widths, header=True, row_bg=None):
        t = Table(data, colWidths=col_widths, repeatRows=1 if header else 0)
        style = [
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#D5D8DC")),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, row_bg or C_ROW_ALT]),
        ]
        if header:
            style += [
                ("BACKGROUND",  (0, 0), (-1, 0), C_BLUE),
                ("TEXTCOLOR",   (0, 0), (-1, 0), C_WHITE),
                ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ]
        t.setStyle(TableStyle(style))
        return t

    # ── Cover & TOC ──────────────────────────────────────────────
    def _cover(self, styles):
        story = [Spacer(1, 0.8 * cm)]
        title_t = Table([[Paragraph("RVR", styles["cover_title"])]], colWidths=[17 * cm])
        title_t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), C_DARK),
            ("TOPPADDING", (0, 0), (-1, -1), 18),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ]))
        story.append(title_t)

        sub_t = Table([[Paragraph("Penetration Assessment Report", styles["cover_sub"])]], colWidths=[17 * cm])
        sub_t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), C_BLUE),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
            ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ]))
        story.append(sub_t)
        story.append(Spacer(1, 1.1 * cm))

        s = self.state
        risk_color = SEV_COLORS.get(self.risk, C_BLUE_LIGHT)
        rows = [
            ["TARGET",          s.target],
            ["TARGET TYPE",     s.target_type.upper()],
            ["HOSTNAME",        s.hostname or "not discovered"],
            ["SCAN PROFILE",    s.profile.upper()],
            ["ATTACKER IP",     f"{s.attacker_ip or 'N/A'} ({s.attacker_iface or 'N/A'})"],
            ["START",           s.start_time[:19].replace("T", " ")],
            ["RISK RATING",     self.risk],
            ["FINDINGS",        f"{len(self.findings)} "
                                 f"({self.builder.counts().get('Critical', 0)} critical / "
                                 f"{self.builder.counts().get('High', 0)} high)"],
            ["OPEN PORTS",      str(len(s.open_ports))],
            ["EXPLOIT MATCHES", str(len(s.exploit_matches))],
            ["DATE",            datetime.now().strftime("%Y-%m-%d")],
            ["OPERATOR",        "ryx13"],
            ["CLASSIFICATION",  "CONFIDENTIAL"],
        ]

        detail_t = Table(
            [[Paragraph(k, styles["label"]), Paragraph(self._esc(v), styles["body_bold"])]
             for k, v in rows],
            colWidths=[5 * cm, 12 * cm]
        )
        style_cmds = [
            ("BACKGROUND",    (0, 0), (0, -1), C_GREY_LIGHT),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#D5D8DC")),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ]
        # Highlight the risk row
        for idx, (k, v) in enumerate(rows):
            if k == "RISK RATING":
                style_cmds += [
                    ("TEXTCOLOR", (1, idx), (1, idx), risk_color),
                    ("FONTNAME",  (1, idx), (1, idx), "Helvetica-Bold"),
                ]
        detail_t.setStyle(TableStyle(style_cmds))
        story.append(detail_t)
        story.append(Spacer(1, 1.3 * cm))

        notice_t = Table([[Paragraph(
            "⚠ CONFIDENTIAL — This document contains sensitive security assessment data. "
            "Distribution is restricted to authorised personnel only.",
            styles["body"]
        )]], colWidths=[17 * cm])
        notice_t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), C_ROW_RED),
            ("BOX",           (0, 0), (-1, -1), 1, C_RED),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("TOPPADDING",    (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(notice_t)
        return story

    def _toc(self, styles):
        toc = TableOfContents()
        toc.levelStyles = [
            ParagraphStyle("toc1", fontName="Helvetica-Bold", fontSize=10,
                           textColor=C_GREY_DARK, leftIndent=6, spaceBefore=6),
            ParagraphStyle("toc2", fontName="Helvetica", fontSize=9,
                           textColor=C_GREY_DARK, leftIndent=20, spaceBefore=2),
        ]
        return [Paragraph("Table of Contents", styles["toc_h"]), toc]

    # ── Engagement overview ──────────────────────────────────────
    def _engagement_overview(self, styles):
        story = [Paragraph("1. Engagement Overview", styles["h1"])]

        story.append(Paragraph("1.1 Scope", styles["h2"]))
        s = self.state
        story.append(Paragraph(
            f"An automated reconnaissance assessment was performed against <b>{self._esc(s.target)}</b> "
            f"({s.target_type}"
            + (f", hostname <b>{self._esc(s.hostname)}</b>" if s.hostname else "")
            + f") using the <b>{s.profile}</b> scan profile. All activity originated from "
            f"{self._esc(s.attacker_ip or 'the operator network')} and remained within the authorised scope "
            "of this engagement.",
            styles["body"]))

        story.append(Paragraph("1.2 Methodology", styles["h2"]))
        story.append(Paragraph(
            "The assessment followed a phase-driven methodology: passive OSINT (domain targets), a full TCP "
            "port sweep with service/version detection, conditional deep enumeration of every discovered "
            "service, exploit-DB correlation against identified versions, AI-assisted analysis, and "
            "reporting. Modules fire only when their trigger service is actually present.",
            styles["body"]))

        phases = [
            ["Phase", "Activity", "Tools"],
            ["1 — OSINT", "Subdomain & email discovery (domain targets)", "subfinder, crt.sh, theHarvester"],
            ["2 — Network sweep", "Full TCP port scan + service/version detection", "nmap"],
            ["3 — Enumeration", "Conditional deep dives per open service", "whatweb, ffuf, nuclei, gowitness,\nenum4linux-ng, NetExec, snmpwalk,\nshowmount, ldapsearch, impacket,\nbloodhound-python, certipy"],
            ["3.5 — HTB workflow", "Hostname discovery, /etc/hosts, notes (--htb)", "RVR internal"],
            ["4 — Exploit correlation", "Service versions vs. Exploit-DB", "searchsploit"],
            ["5 — AI analysis", "Findings synthesis, attack paths, next steps", "Gemini / Groq / Claude / OpenAI"],
            ["6 — Reporting", "This deliverable (PDF + Markdown)", "reportlab"],
        ]
        story.append(self._tbl(
            [[Paragraph(c, styles["body"]) for c in row] for row in phases],
            [3.6 * cm, 6.4 * cm, 7 * cm]))

        story.append(Paragraph("1.3 Timeframe", styles["h2"]))
        elapsed = "N/A"
        try:
            start = datetime.fromisoformat(s.start_time)
            end = datetime.fromisoformat(s.end_time or datetime.now().isoformat())
            secs = int((end - start).total_seconds())
            elapsed = f"{secs // 60}m {secs % 60}s"
        except Exception:
            pass
        meta_rows = [
            ["Parameter", "Value"],
            ["Start time", s.start_time[:19]],
            ["End time", (s.end_time or datetime.now().isoformat())[:19]],
            ["Duration", elapsed],
            ["Modules completed", ", ".join(s.completed_modules) or "None"],
            ["Modules failed", ", ".join(s.failed_modules) or "None"],
        ]
        story.append(self._tbl(meta_rows, [5 * cm, 12 * cm]))
        return story

    # ── Executive summary ────────────────────────────────────────
    def _executive_summary(self, styles):
        story = [Paragraph("2. Executive Summary", styles["h1"])]
        s = self.state

        if s.ai_summary:
            story.append(Paragraph(self._esc(s.ai_summary), styles["body"]))
        else:
            counts = self.builder.counts()
            parts = [f"Automated reconnaissance against {self._esc(s.target)} identified "
                     f"{len(s.open_ports)} open service(s) and produced {len(self.findings)} findings "
                     f"({counts.get('Critical', 0)} critical, {counts.get('High', 0)} high, "
                     f"{counts.get('Medium', 0)} medium)."]
            if s.exploit_matches:
                parts.append(f"Public exploit code is available for {len(s.exploit_matches)} matched service version(s).")
            if s.captured_hashes:
                parts.append(f"{len(s.captured_hashes)} crackable Kerberos hash(es) were captured without credentials.")
            parts.append("The overall risk rating reflects the most severe observed condition.")
            story.append(Paragraph(" ".join(parts), styles["body"]))

        if s.ai_risk_justification:
            story.append(Spacer(1, 0.2 * cm))
            story.append(Paragraph(f"Risk rationale: {self._esc(s.ai_risk_justification)}", styles["quote"]))

        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("Key figures", styles["h2"]))
        stats = [
            ["Open services", str(len(s.open_ports))],
            ["Web paths enumerated", str(len(s.web_findings))],
            ["Nuclei detections", str(len(s.nuclei_findings))],
            ["Public exploit matches", str(len(s.exploit_matches))],
            ["Captured crackable hashes", str(len(s.captured_hashes))],
            ["Findings in this report", str(len(self.findings))],
        ]
        story.append(self._tbl(
            [[Paragraph(a, styles["body"]), Paragraph(b, styles["body_bold"])] for a, b in stats],
            [8 * cm, 9 * cm], header=False))

        top = self.findings[:5]
        if top:
            story.append(Paragraph("Top findings at a glance", styles["h2"]))
            rows = [["ID", "Severity", "Finding"]]
            for f in top:
                rows.append([
                    f.fid,
                    Paragraph(f'<font color="{SEV_COLORS[f.severity].hexval()[2:] if hasattr(SEV_COLORS[f.severity], "hexval") else "000000"}">'
                              f'{f.severity}</font>' if False else f.severity, styles["body_bold"]),
                    Paragraph(self._esc(f.title), styles["body"]),
                ])
            tbl = self._tbl(rows, [1.8 * cm, 2.6 * cm, 12.6 * cm])
            # severity text colors
            style_cmds = [("TEXTCOLOR", (1, i), (1, i), SEV_COLORS.get(f.severity, C_BLACK)) for i, f in enumerate(top, start=1)]
            style_cmds += [("FONTNAME", (1, i), (1, i), "Helvetica-Bold") for i in range(1, len(top) + 1)]
            tbl.setStyle(TableStyle(style_cmds))
            story.append(tbl)

        story.append(Spacer(1, 0.4 * cm))
        return story

    # ── Risk summary ─────────────────────────────────────────────
    def _risk_summary(self, styles):
        story = [Paragraph("3. Risk Summary", styles["h1"])]
        counts = self.builder.counts()

        story.append(Paragraph(
            f"Overall risk rating: <b>{self.risk}</b> — derived from the most severe finding and the "
            "aggregate attack surface. Findings are graded Critical (immediate compromise potential), "
            "High (significant exposure), Medium (meaningful weakness), Low (hardening opportunity) and "
            "Informational (context).",
            styles["body"]))
        story.append(Spacer(1, 0.25 * cm))

        rows = [["Severity", "Count", "Meaning"]]
        meanings = {
            "Critical": "Directly exploitable to full compromise of the target",
            "High": "Serious exposure enabling significant attacker capability",
            "Medium": "Weakness that meaningfully assists an attacker",
            "Low": "Hygiene issue / hardening opportunity",
            "Informational": "Context useful for follow-on testing",
        }
        for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
            rows.append([sev, str(counts.get(sev, 0)), meanings[sev]])
        tbl = self._tbl(rows, [3.2 * cm, 2 * cm, 11.8 * cm])
        for i, sev in enumerate(["Critical", "High", "Medium", "Low", "Informational"], start=1):
            if counts.get(sev, 0):
                tbl.setStyle(TableStyle([
                    ("TEXTCOLOR", (0, i), (1, i), SEV_COLORS[sev]),
                    ("FONTNAME", (0, i), (1, i), "Helvetica-Bold"),
                    ("BACKGROUND", (0, i), (-1, i), SEV_ROW_BG[sev]),
                ]))
        story.append(tbl)
        story.append(Spacer(1, 0.4 * cm))
        return story

    # ── Detailed findings ────────────────────────────────────────
    def _detailed_findings(self, styles):
        story = [Paragraph("4. Detailed Findings", styles["h1"])]
        if not self.findings:
            story.append(Paragraph(
                "No findings were produced by this scan — either the target exposed no notable services, "
                "or all modules completed without flagging a condition. See the appendices for raw enumeration data.",
                styles["body"]))
            return story

        story.append(Paragraph(
            f"{len(self.findings)} finding(s), ordered by severity. Each finding documents what was observed, "
            "the evidence it rests on, the impact if abused, and specific remediation guidance.",
            styles["body"]))

        for f in self.findings:
            sev_color = SEV_COLORS.get(f.severity, C_GREY_DARK)

            # Header bar: F-001 | severity | title
            header = Table(
                [[Paragraph(f"<b>{f.fid}</b>", ParagraphStyle("fid", parent=styles["body"], textColor=C_WHITE)),
                  Paragraph(f.severity.upper(), ParagraphStyle("sev", parent=styles["body"], textColor=C_WHITE, alignment=2)),
                  ]],
                colWidths=[12.4 * cm, 4.6 * cm]
            )
            header.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, 0), C_DARK),
                ("BACKGROUND", (1, 0), (1, 0), sev_color),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
            ]))

            title = Paragraph(f"<b>{f.title}</b>", ParagraphStyle(
                "ftitle", parent=styles["h2"], fontSize=11, textColor=C_DARK))

            meta_rows = [
                ["Category", f.category],
                ["Affected", f.affected],
                ["Source", f.source],
            ]
            meta = self._tbl(
                [[Paragraph(a, styles["label"]), Paragraph(self._esc(b), styles["body"])] for a, b in meta_rows],
                [3 * cm, 14 * cm], header=False)

            block = [header, Spacer(1, 0.15 * cm), title, Spacer(1, 0.1 * cm), meta, Spacer(1, 0.15 * cm)]

            if f.description:
                block.append(Paragraph("Description", styles["h3"]))
                block.append(Paragraph(self._esc(f.description), styles["body"]))
            if f.evidence:
                block.append(Paragraph("Evidence", styles["h3"]))
                block.append(Paragraph(self._esc(f.evidence).replace("\n", "<br/>"), styles["code"]))
            if f.reproduction:
                block.append(Paragraph("Reproduction", styles["h3"]))
                block.append(Paragraph(self._esc(f.reproduction).replace("\n", "<br/>"), styles["code"]))
            if f.impact:
                block.append(Paragraph("Impact", styles["h3"]))
                block.append(Paragraph(self._esc(f.impact), styles["body"]))
            if f.remediation:
                block.append(Paragraph("Remediation", styles["h3"]))
                block.append(Paragraph(self._esc(f.remediation), styles["body"]))
            if f.references:
                block.append(Paragraph("References", styles["h3"]))
                block.append(Paragraph(self._esc("; ".join(f.references)), styles["body"]))

            story.append(KeepTogether(block[:6]))  # header + meta stay together
            story.extend(block[6:])
            story.append(Spacer(1, 0.35 * cm))

        return story

    # ── Attack paths ─────────────────────────────────────────────
    def _attack_paths(self, styles):
        s = self.state
        paths = s.ai_attack_paths
        story = [Paragraph("5. Attack Path Analysis", styles["h1"])]

        if paths:
            story.append(Paragraph(
                "The following chains combine observed weaknesses into realistic attack routes, mapped to "
                "MITRE ATT&CK where applicable. Paths are analytical hypotheses for authorised testing — "
                "prerequisites must hold for a path to be viable.",
                styles["body"]))
            for i, p in enumerate(paths, start=1):
                steps = p.get("steps", [])
                block = [
                    Paragraph(f"Path {i}: {self._esc(p.get('name', 'unnamed'))}", styles["h2"]),
                ]
                if p.get("mitre"):
                    block.append(Paragraph(f"MITRE ATT&CK: {self._esc(p['mitre'])}", styles["quote"]))
                if p.get("prerequisites"):
                    block.append(Paragraph(f"<b>Prerequisites:</b> {self._esc(p['prerequisites'])}", styles["body"]))
                if steps:
                    block.append(Paragraph("Steps", styles["h3"]))
                    for j, step in enumerate(steps, start=1):
                        block.append(Paragraph(f"{j}. {self._esc(step)}", styles["body"]))
                if p.get("impact"):
                    block.append(Paragraph(f"<b>Impact:</b> {self._esc(p['impact'])}", styles["body"]))
                story.append(KeepTogether(block))
                story.append(Spacer(1, 0.25 * cm))
        else:
            story.append(Paragraph(
                "AI attack-path analysis was not available for this scan (no provider configured or "
                "analysis skipped). Deterministic findings in section 4 document every individually "
                "observed weakness; chain them manually using the appendix data.",
                styles["body"]))

        if s.ai_vectors and not paths:
            story.append(Paragraph("Identified attack vectors", styles["h2"]))
            for v in s.ai_vectors:
                story.append(Paragraph(f"• {self._esc(v)}", styles["body"]))

        story.append(Spacer(1, 0.4 * cm))
        return story

    # ── Remediation roadmap ──────────────────────────────────────
    def _remediation_roadmap(self, styles):
        story = [Paragraph("6. Remediation Roadmap", styles["h1"])]
        story.append(Paragraph(
            "Fixes are sequenced by severity so effort lands where risk reduction is highest. Verify each "
            "fix with the reproduction step of the corresponding finding.",
            styles["body"]))

        bands = [
            ("Immediate (0–7 days)", ["Critical", "High"],
             "Address before any other work: these enable direct compromise or major attacker capability."),
            ("Short term (2–4 weeks)", ["Medium"],
             "Plan into the next change window; meaningful attacker assistance."),
            ("Ongoing hardening", ["Low", "Informational"],
             "Fold into standard hygiene cycles and architecture reviews."),
        ]
        for title, sevs, blurb in bands:
            items = [f for f in self.findings if f.severity in sevs]
            block = [Paragraph(title, styles["h2"]), Paragraph(blurb, styles["body"])]
            if items:
                rows = [["ID", "Finding", "Fix summary"]]
                for f in items:
                    rows.append([
                        f.fid,
                        Paragraph(self._esc(f.title), styles["body"]),
                        Paragraph(self._esc(f.remediation[:160]) + ("…" if len(f.remediation) > 160 else ""), styles["body"]),
                    ])
                block.append(self._tbl(rows, [1.7 * cm, 6.3 * cm, 9 * cm]))
            else:
                block.append(Paragraph("No findings in this band.", styles["quote"]))
            story.append(KeepTogether(block))
            story.append(Spacer(1, 0.25 * cm))

        story.append(Spacer(1, 0.3 * cm))
        return story

    # ── Appendices ───────────────────────────────────────────────
    def _appendix_network(self, styles):
        if not self.state.open_ports:
            return []
        story = [Paragraph("Appendix A — Network Enumeration", styles["h1"])]
        story.append(Paragraph(
            f"{len(self.state.open_ports)} open port(s) identified on {self.state.target}.",
            styles["body"]))
        rows = [["Port", "Protocol", "Service", "Version / Banner"]]
        for p in sorted(self.state.open_ports, key=lambda x: x["port"]):
            rows.append([
                str(p["port"]), p["proto"].upper(), p["service"],
                Paragraph(self._esc(p.get("version", ""))[:70], styles["body"]),
            ])
        story.append(self._tbl(rows, [2 * cm, 2.5 * cm, 3 * cm, 9.5 * cm]))

        scripts_found = [(p["port"], p["service"], sid, out)
                         for p in self.state.open_ports
                         for sid, out in (p.get("scripts") or {}).items()
                         if out.strip()]
        if scripts_found:
            story.append(Paragraph("Nmap NSE output (highlights)", styles["h2"]))
            for port, svc, script_id, output in scripts_found[:12]:
                story.append(Paragraph(f"<b>{port}/{svc} — {script_id}</b>", styles["body_bold"]))
                story.append(Paragraph(self._esc(output.strip())[:400].replace("\n", "<br/>"), styles["code"]))
        story.append(Spacer(1, 0.4 * cm))
        return story

    def _appendix_web(self, styles):
        s = self.state
        if not (s.web_findings or s.web_technologies or s.vhosts or s.ssl_certs):
            return []
        story = [Paragraph("Appendix B — Web Enumeration", styles["h1"])]

        if s.web_technologies:
            clean = [t for t in s.web_technologies if t and "RESERVED" not in t and len(t) > 1]
            if clean:
                story.append(Paragraph(f"<b>Detected technologies:</b> {self._esc(', '.join(clean))}", styles["body"]))
                story.append(Spacer(1, 0.2 * cm))

        if s.ssl_certs:
            story.append(Paragraph("TLS certificates", styles["h2"]))
            rows = [["Port", "Subject CN", "SAN entries", "Issuer", "Valid until"]]
            for c in s.ssl_certs:
                rows.append([
                    str(c.get("port", "")),
                    self._esc(c.get("cn", "n/a"))[:24],
                    self._esc(", ".join((c.get("san") or [])[:3]))[:40],
                    self._esc(c.get("issuer", "n/a"))[:30],
                    self._esc(c.get("valid_to", "n/a"))[:16],
                ])
            story.append(self._tbl(rows, [1.4 * cm, 3.4 * cm, 4.4 * cm, 4.4 * cm, 3.4 * cm]))

        if s.vhosts:
            story.append(Paragraph("Virtual hosts", styles["h2"]))
            rows = [["Host", "Status", "Size"]]
            for v in s.vhosts[:40]:
                rows.append([v.get("host_full", v.get("host", "?")), str(v.get("status", "")), str(v.get("size", ""))])
            story.append(self._tbl(rows, [9 * cm, 3 * cm, 5 * cm]))

        findings = s.web_findings
        if findings:
            cats = {
                "Accessible (2xx)": ([f for f in findings if f["status"] in [200, 201, 204]], C_ROW_GREEN),
                "Authentication Required (4xx)": ([f for f in findings if f["status"] in [401, 403]], C_ROW_YELLOW),
                "Redirects (3xx)": ([f for f in findings if f["status"] in [301, 302, 307]][:30], C_ROW_ALT),
                "Server Errors (5xx)": ([f for f in findings if f["status"] >= 500], C_ROW_RED),
            }
            for title, (rows_data, bg) in cats.items():
                if not rows_data:
                    continue
                story.append(Paragraph(f"{title} — {len(rows_data)}", styles["h2"]))
                rows = [["Status", "URL", "Size", "Source"]]
                for f in rows_data[:100]:
                    rows.append([str(f["status"]), Paragraph(self._esc(f["url"])[:90], styles["body"]),
                                 str(f.get("size", "")), f.get("source", "ffuf")])
                t = Table(rows, colWidths=[1.8 * cm, 10.6 * cm, 1.6 * cm, 3 * cm])
                t.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), C_BLUE),
                    ("TEXTCOLOR", (0, 0), (-1, 0), C_WHITE),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, bg]),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D5D8DC")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]))
                story.append(t)
                if len(rows_data) > 100:
                    story.append(Paragraph(f"... and {len(rows_data) - 100} more — see raw ffuf output.", styles["body"]))

        if s.nuclei_findings:
            story.append(Paragraph("Nuclei detections", styles["h2"]))
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_findings = sorted(
                s.nuclei_findings,
                key=lambda x: sev_order.get(x.get("info", {}).get("severity", "info").lower(), 5)
            )
            rows = [["Severity", "Template ID", "Name", "Matched At"]]
            for f in sorted_findings[:50]:
                info = f.get("info", {})
                rows.append([info.get("severity", "unknown").upper(),
                             f.get("template-id", "N/A")[:25],
                             Paragraph(self._esc(info.get("name", "N/A"))[:40], styles["body"]),
                             self._esc(f.get("matched-at", "N/A"))[:50]])
            t = self._tbl(rows, [2.2 * cm, 4.5 * cm, 5.5 * cm, 4.8 * cm])
            for i, f in enumerate(sorted_findings[:50], start=1):
                sev = f.get("info", {}).get("severity", "unknown").upper()
                if sev in SEV_COLORS:
                    t.setStyle(TableStyle([
                        ("TEXTCOLOR", (0, i), (0, i), SEV_COLORS[sev]),
                        ("FONTNAME", (0, i), (0, i), "Helvetica-Bold"),
                    ]))
            story.append(t)

        story.append(Spacer(1, 0.4 * cm))
        return story

    def _appendix_ad(self, styles):
        s = self.state
        sections = []
        smb, ldap, krb, bh, adcs = s.smb_findings, s.ldap_findings, s.kerberos_findings, s.bloodhound_findings, s.adcs_findings
        if not (smb or ldap or krb or bh or adcs or s.rdp_findings):
            return []

        story = [Paragraph("Appendix C — Directory Services Enumeration", styles["h1"])]

        if smb:
            rows = [["Property", "Value"]]
            for key in ["signing", "anonymous_login", "os", "domain"]:
                if key in smb:
                    val = smb[key]
                    if isinstance(val, dict):
                        val = json.dumps(val)[:80]
                    rows.append([key.replace("_", " ").title(), self._esc(str(val))[:70]])
            if len(rows) > 1:
                story.append(Paragraph("SMB", styles["h2"]))
                story.append(self._tbl(rows, [5 * cm, 12 * cm]))
            if smb.get("shares"):
                story.append(Paragraph(f"Shares ({len(smb['shares'])})", styles["h3"]))
                story.append(self._tbl([["Share"]] + [[x] for x in smb["shares"][:30]], [17 * cm]))
            users = smb.get("users") or []
            if users:
                story.append(Paragraph(f"Users via RID/enum4linux ({len(users)})", styles["h3"]))
                rows = [["Username"]] + [[u] for u in users[:60]]
                story.append(self._tbl(rows, [17 * cm]))

        if ldap:
            story.append(Paragraph("LDAP", styles["h2"]))
            rows = [["Property", "Value"]]
            if "anonymous_bind" in ldap:
                rows.append(["Anonymous bind", "ALLOWED" if ldap["anonymous_bind"] else "DENIED"])
            for key in ["domain", "default_naming_context"]:
                if ldap.get(key):
                    rows.append([key.replace("_", " ").title(), self._esc(str(ldap[key]))[:70]])
            if len(rows) > 1:
                story.append(self._tbl(rows, [5 * cm, 12 * cm]))
            anon_users = ldap.get("anonymous_users") or []
            if anon_users:
                story.append(Paragraph(f"Accounts enumerable anonymously ({len(anon_users)})", styles["h3"]))
                rows = [["Account"]] + [[self._esc(u)] for u in anon_users[:60]]
                story.append(self._tbl(rows, [17 * cm]))

        if krb:
            story.append(Paragraph("Kerberos", styles["h2"]))
            rows = [["Property", "Value"]]
            if krb.get("valid_users"):
                rows.append(["Kerbrute valid users", str(len(krb["valid_users"]))])
            asrep = krb.get("asrep_roast", {})
            if asrep:
                rows.append(["AS-REP roastable", f"{asrep.get('count', 0)} ({', '.join(asrep.get('accounts', [])[:8])})"])
            kerb = krb.get("kerberoast", {})
            if kerb:
                rows.append(["Kerberoastable", f"{kerb.get('count', 0)} ({', '.join(kerb.get('accounts', [])[:8])})"])
            if len(rows) > 1:
                story.append(self._tbl(rows, [5 * cm, 12 * cm]))

        if s.rdp_findings:
            story.append(Paragraph("RDP", styles["h2"]))
            rows = [["Property", "Value"]]
            d = s.rdp_findings
            for key, label in [("dns_computer", "Hostname (DNS)"), ("netbios_computer", "Hostname (NetBIOS)"),
                               ("dns_domain", "Domain (DNS)"), ("netbios_domain", "Domain (NetBIOS)"),
                               ("os_build", "OS Build")]:
                if d.get(key):
                    rows.append([label, self._esc(str(d[key]))[:70]])
            if "nla_enabled" in d:
                rows.append(["NLA enforced", "Yes" if d["nla_enabled"] else "No"])
            if d.get("security_protocols"):
                rows.append(["Security protocols", ", ".join(d["security_protocols"])])
            if len(rows) > 1:
                story.append(self._tbl(rows, [5 * cm, 12 * cm]))

        if bh:
            story.append(Paragraph("BloodHound", styles["h2"]))
            if bh.get("zip_path"):
                story.append(Paragraph(
                    f"Collection data captured ({bh.get('mode')}) and stored at <b>{self._esc(bh['zip_path'])}</b> — "
                    "ingest into BloodHound CE for attack-path analysis.", styles["body"]))
            elif bh.get("manual_commands"):
                story.append(Paragraph(
                    f"Collection deferred; manual workflow documented at {self._esc(bh['manual_commands'])}.",
                    styles["body"]))

        if adcs:
            story.append(Paragraph("AD CS", styles["h2"]))
            if adcs.get("web_enrollment"):
                story.append(Paragraph(
                    f"Web enrollment exposed at {self._esc(adcs['web_enrollment'].get('url', ''))}.", styles["body"]))
            if adcs.get("vulnerable_templates"):
                story.append(Paragraph(
                    f"Vulnerable templates: {self._esc(' '.join(adcs['vulnerable_templates'].get('esc_classes', [])))}.",
                    styles["body"]))
            if adcs.get("manual_commands"):
                story.append(Paragraph(
                    f"Manual workflow: {self._esc(adcs['manual_commands'])}", styles["body"]))

        story.append(Spacer(1, 0.4 * cm))
        return story

    def _appendix_hashes(self, styles):
        s = self.state
        if not s.captured_hashes:
            return []
        story = [Paragraph("Appendix D — Captured Hash Material", styles["h1"])]
        story.append(Paragraph(
            f"{len(s.captured_hashes)} crackable hash(es) were captured during enumeration. Cracking "
            "commands were generated automatically in the loot directory.",
            styles["body"]))
        rows = [["Type", "Account", "Hash (truncated)", "Cracking command"]]
        for h in s.captured_hashes[:30]:
            rows.append([
                h["type"], h["account"],
                Paragraph(self._esc(h["hash"])[:36], styles["body"]),
                Paragraph(self._esc(h["crack_cmd"])[:52], styles["body"]),
            ])
        story.append(self._tbl(rows, [2.4 * cm, 3 * cm, 5.3 * cm, 6.3 * cm]))
        story.append(Spacer(1, 0.4 * cm))
        return story

    def _appendix_exploits(self, styles):
        if not self.state.exploit_matches:
            return []
        story = [Paragraph("Appendix E — Exploit-DB Correlation", styles["h1"])]
        story.append(Paragraph(
            f"{len(self.state.exploit_matches)} public exploit(s) matched identified service versions. "
            "Mirror an exploit locally with `searchsploit -m <EDB-ID>` and review it before use.",
            styles["body"]))
        rows = [["Port", "EDB-ID", "Title", "Type", "Date"]]
        for m in self.state.exploit_matches[:60]:
            rows.append([
                str(m["port"]), m["id"],
                Paragraph(self._esc(m["title"])[:70], styles["body"]),
                m["type"], m["date"][:10],
            ])
        story.append(self._tbl(rows, [1.6 * cm, 2 * cm, 8.2 * cm, 2.4 * cm, 2.8 * cm]))
        story.append(Spacer(1, 0.4 * cm))
        return story

    def _appendix_osint(self, styles):
        s = self.state
        if not (s.subdomains or s.emails):
            return []
        story = [Paragraph("Appendix F — Passive OSINT", styles["h1"])]
        if s.subdomains:
            story.append(Paragraph(f"Subdomains ({len(s.subdomains)})", styles["h2"]))
            rows = [["Subdomain"]] + [[x] for x in s.subdomains[:100]]
            story.append(self._tbl(rows, [17 * cm]))
        if s.emails:
            story.append(Paragraph(f"Email addresses ({len(s.emails)})", styles["h2"]))
            rows = [["Email"]] + [[x] for x in s.emails[:50]]
            story.append(self._tbl(rows, [17 * cm]))
        story.append(Spacer(1, 0.4 * cm))
        return story

    def _appendix_screenshots(self, styles):
        s = self.state
        if not s.screenshots:
            return []
        story = [Paragraph("Appendix G — Web Screenshots", styles["h1"])]
        story.append(Paragraph(f"{len(s.screenshots)} screenshot(s) captured.", styles["body"]))
        story.append(Spacer(1, 0.2 * cm))
        max_width = 16 * cm
        for shot in s.screenshots:
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
                story.append(Paragraph(self._esc(url), styles["body_bold"]))
                story.append(img)
                story.append(Spacer(1, 0.4 * cm))
            except Exception as e:
                log_warn(f"Could not embed screenshot {path}: {e}")
        return story

    def _appendix_artifacts(self, styles):
        story = [Paragraph("Appendix H — Output Artifacts", styles["h1"])]
        story.append(Paragraph(
            "All raw tool output is retained in the engagement directory for verification and re-testing:",
            styles["body"]))
        story.append(Paragraph(str(self.state.output_dir), styles["code"]))
        story.append(Spacer(1, 0.3 * cm))
        if self.state.artifacts:
            rows = [["Artifact", "Path"]]
            for key, path in list(self.state.artifacts.items())[:40]:
                rows.append([key, Paragraph(self._esc(str(path))[:90], styles["body"])])
            story.append(self._tbl(rows, [4.5 * cm, 12.5 * cm]))
        return story
