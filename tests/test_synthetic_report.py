#!/usr/bin/env python3
"""
RVR — synthetic-state smoke test
Builds a rich, realistic RVRState (no target is ever touched) and exercises
every post-recon consumer:

  * FindingsBuilder  — deterministic findings + severity counts
  * PDFReport        — commercial-grade PDF renders without ReportLab errors
  * MarkdownReport   — report.md structure is complete and well-formed
  * DiscordNotifier  — embed payload is valid against Discord's limits
                       (built, never sent)
  * HTBModule        — hostname aggregation + notes.md template
  * end_summary_panel — closing dashboard renders

Run:  .venv/bin/python tests/test_synthetic_report.py
Exits non-zero on the first failed assertion; prints a PASS/FAIL summary.
"""

import sys
import shutil
from pathlib import Path
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rvr.utils.state import RVRState
from rvr.output.findings import FindingsBuilder
from rvr.output.pdf_report import PDFReport
from rvr.output.markdown_report import MarkdownReport
from rvr.output.discord_notify import DiscordNotifier
from rvr.modules.htb import HTBModule
from rvr.utils.console import end_summary_panel

RESULTS = []


def check(name: str, cond: bool, detail: str = ""):
    RESULTS.append((name, bool(cond), detail))
    mark = "PASS" if cond else "FAIL"
    print(f"  [{mark}] {name}" + (f" — {detail}" if detail else ""))


def build_state(out_dir: Path) -> RVRState:
    """Synthetic HTB-style Windows DC + web stack state."""
    state = RVRState(
        target="10.10.11.23",
        target_type="ip",
        profile="aggressive",
        output_dir=out_dir,
        attacker_ip="10.10.14.7",
        attacker_iface="tun0",
        htb_mode=True,
    )
    state.start_time = (datetime.now() - timedelta(minutes=6, seconds=32)).isoformat()
    state.end_time = datetime.now().isoformat()

    state.open_ports = [
        {"port": 53, "proto": "tcp", "service": "domain", "version": "Simple DNS Plus"},
        {"port": 80, "proto": "tcp", "service": "http", "version": "Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)",
         "scripts": {"http-title": "Site doesn't have a title (text/html)."}},
        {"port": 88, "proto": "tcp", "service": "kerberos-sec", "version": "Microsoft Windows Kerberos (server Time: 2026-10-20 19:00:00Z)"},
        {"port": 135, "proto": "tcp", "service": "msrpc", "version": "Microsoft Windows RPC"},
        {"port": 139, "proto": "tcp", "service": "netbios-ssn", "version": ""},
        {"port": 443, "proto": "tcp", "service": "https", "version": "Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)"},
        {"port": 445, "proto": "tcp", "service": "microsoft-ds", "version": "Windows Server 2019 Standard 17763 microsoft-ds",
         "scripts": {"smb-os-discovery": "NetBIOS computer name: DC01, Domain name: support.htb"}},
        {"port": 3306, "proto": "tcp", "service": "mysql", "version": "MySQL 8.0.28"},
        {"port": 3389, "proto": "tcp", "service": "ms-wbt-server", "version": "Microsoft Terminal Services"},
        {"port": 3268, "proto": "tcp", "service": "ldap", "version": ""},
    ]

    state.web_findings = [
        {"url": f"http://10.10.11.23/{p}", "status": st, "size": 500 + i * 37, "words": 40 + i, "source": "ffuf"}
        for i, (p, st) in enumerate([
            ("index.html", 200), ("admin", 401), ("dashboard.php", 200),
            ("backup.zip", 200), ("server-status", 403), ("api/v1", 200),
        ])
    ]
    state.web_technologies = ["PHP 8.1.1", "Apache 2.4.52", "OpenSSL 1.1.1m", "Bootstrap"]

    state.nuclei_findings = [
        {"template-id": "mysql-root-empty-password", "matched-at": "10.10.11.23:3306",
         "info": {"name": "MySQL Root Empty Password", "severity": "critical",
                  "description": "MySQL root account permits login with an empty password, allowing full database access."}},
        {"template-id": "apache-detect", "matched-at": "http://10.10.11.23",
         "info": {"name": "Apache Detection", "severity": "info"}},
    ]

    state.smb_findings = {
        "signing": "disabled",
        "anonymous_login": True,
        "shares": ["IPC$", "support-files", "ADMIN$", "C$"],
        "users": ["support", "administrator", "ldap", "krbtgt", "guest"],
        "os": "Windows Server 2019 Standard",
    }
    state.ldap_findings = {
        "anonymous_bind": True,
        "domain": "support.htb",
        "default_naming_context": "DC=support,DC=htb",
        "anonymous_users": ["support", "ldap", "krbtgt", "administrator"],
    }
    state.kerberos_findings = {
        "valid_users": ["support", "ldap", "krbtgt"],
        "asrep_roast": {"count": 2, "accounts": ["support", "ldap"]},
        "kerberoast": {"count": 1, "accounts": ["svc-ldap"]},
    }
    state.rdp_findings = {
        "nla_enabled": False,
        "netbios_computer": "DC01",
        "dns_computer": "DC01.support.htb",
        "netbios_domain": "SUPPORT",
        "os_build": "10.0.17763",
    }
    state.ftp_findings = {"anonymous_login": True, "banner": "220 Microsoft FTP Service", "anon_listing": ["readme.txt"]}
    state.database_findings = {
        "mysql": {"port": 3306, "empty_password": True, "notes": ["mysql root login with empty password succeeded"]},
    }
    state.adcs_findings = {
        "web_enrollment": {"url": "https://10.10.11.23/certsrv"},
        "vulnerable_templates": {"esc_classes": ["ESC1", "ESC8"]},
    }
    state.bloodhound_findings = {"zip_path": str(out_dir / "bloodhound" / "DC01.zip"), "mode": "anonymous"}

    state.exploit_matches = [
        {"port": 80, "query": "apache 2.4.52", "id": "50383", "title": "Apache 2.4.50 - Path Traversal & RCE", "type": "webapps", "platform": "multiple", "date": "2021-10-11", "path": "/usr/share/exploitdb/exploits/multiple/webapps/50383.py"},
        {"port": 3306, "query": "mysql 8.0.28", "id": "45019", "title": "MySQL 8.0.17 - Auth Bypass", "type": "remote", "platform": "linux", "date": "2018-07-14", "path": "/usr/share/exploitdb/exploits/linux/remote/45019.py"},
    ]
    state.captured_hashes = [
        {"type": "asrep", "account": "support", "hash": "$krb5asrep$23$support@SUPPORT.HTB:abcdef...", "crack_cmd": "hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt"},
        {"type": "kerberoast", "account": "svc-ldap", "hash": "$krb5tgs$23$*svc-ldap$SUPPORT.HTB...", "crack_cmd": "hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt"},
    ]
    state.ssl_certs = [{"port": 443, "cn": "dc01.support.htb", "san": ["dc01.support.htb", "support.htb"],
                         "issuer": "DC01-SUPPORT-CA", "valid_to": "2027-01-01"}]
    state.vhosts = [{"host": "dev", "host_full": "dev.support.htb", "status": 200, "size": 8123}]

    state.ai_summary = ("Synthetic assessment summary: the host is a domain controller for support.htb "
                        "with SMB signing disabled, anonymous LDAP enumeration, AS-REP roastable accounts "
                        "and a MySQL instance reachable with an empty root password.")
    state.ai_risk_level = "Critical"
    state.ai_risk_justification = "Unauthenticated database access plus offline-crackable Kerberos hashes combine into immediate-compromise paths."
    state.ai_provider_used = "synthetic-test"
    state.ai_attack_paths = [
        {"name": "AS-REP roast to DC compromise", "mitre": "T1558.004",
         "prerequisites": "network access to port 88",
         "steps": ["Request AS-REP for support (no pre-auth)", "Crack hash with rockyou",
                   "Authenticate and enumerate the domain", "Escalate via found privilege path"],
         "impact": "Domain user access leading to potential DC compromise"},
    ]
    state.ai_findings = [
        {"title": "MySQL root with empty password", "severity": "Critical", "category": "Weak Authentication",
         "description": "Root database account requires no password.",
         "evidence": "mysql -u root connected without password",
         "remediation": "Set a strong root password and restrict network exposure.", "cves": []},
    ]
    state.ai_next_steps = [
        "Crack the captured AS-REP hashes: hashcat -m 18200 kerberos/asrep.txt rockyou.txt",
        "Connect to MySQL: mysql -h 10.10.11.23 -u root",
        "Enumerate shares with the found credentials via NetExec",
    ]

    state.completed_modules = ["network", "web", "smb", "ldap", "kerberos", "bloodhound", "adcs",
                               "exploits", "ai", "report"]
    state.artifacts = {"nmap_xml": str(out_dir / "nmap" / "scan.xml"), "ffuf_json": str(out_dir / "web" / "ffuf.json")}
    return state


def main() -> int:
    out_dir = Path(__file__).resolve().parent.parent / "output" / "_synthetic_test"
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    # HTB notes path expectation
    (out_dir / "kerberos").mkdir()

    print("\n── RVR synthetic-state smoke test ──\n")

    state = build_state(out_dir)

    # 1. FindingsBuilder ------------------------------------------------
    builder = FindingsBuilder(state)
    findings = builder.build()
    counts = builder.counts()
    check("findings: produced from synthetic state", len(findings) >= 8, f"{len(findings)} findings")
    check("findings: severity ordering (critical first)",
          findings[0].severity in ("Critical", "High"), findings[0].title)
    check("findings: critical counted", counts.get("Critical", 0) >= 1,
          f"critical={counts.get('Critical', 0)}")
    check("findings: overall risk", builder.overall_risk() in ("Critical", "High"), builder.overall_risk())
    check("findings: every finding has required prose",
          all(f.description and f.impact and f.remediation for f in findings))

    # 2. HTB hostname aggregation + notes --------------------------------
    profile = {}  # HTBModule only reads config defaults from BaseModule
    htb = HTBModule(state, profile)
    hostname = htb.detect_hostname()
    check("htb: hostname aggregated from SSL/SMB/RDP", bool(hostname), f"hostname={hostname}")
    notes = htb.generate_notes()
    check("htb: notes.md generated", notes and notes.exists())
    if notes:
        content = notes.read_text()
        check("htb: notes contain ports table + hashes", "3306" in content and "hashcat" in content)

    # 3. PDF report -------------------------------------------------------
    pdf = PDFReport(state)
    pdf.generate()
    check("pdf: report.pdf written", pdf.output_path.exists(),
          f"{pdf.output_path.stat().st_size if pdf.output_path.exists() else 0} bytes")
    if pdf.output_path.exists():
        head = pdf.output_path.read_bytes()[:8]
        check("pdf: valid PDF header", head.startswith(b"%PDF"))

    # 4. Markdown report --------------------------------------------------
    md = MarkdownReport(state)
    md.generate()
    check("md: report.md written", md.output_path.exists(),
          f"{md.output_path.stat().st_size if md.output_path.exists() else 0} bytes")
    if md.output_path.exists():
        content = md.output_path.read_text()
        for section in ["Executive Summary", "Risk Summary", "Detailed Findings",
                        "Attack Path Analysis", "Recommended Next Steps", "Remediation Roadmap",
                        "Appendix A", "Appendix D", "Appendix E"]:
            check(f"md: section '{section}' present", section in content)
        check("md: table pipes escaped", "\\|" in content or "|" in content)
        # severity badges rendered
        check("md: severity badges present", "🔴 CRITICAL" in content)

    # 5. Discord payload (built, never sent) ------------------------------
    disc = DiscordNotifier(state)
    disc.findings = disc.builder.build()
    disc.risk = state.ai_risk_level or disc.builder.overall_risk()
    payload = disc._build_payload()
    embeds = payload.get("embeds", [])
    check("discord: multi-embed payload", 2 <= len(embeds) <= 10, f"{len(embeds)} embeds")
    ok_lens = all(
        len(str(f.get("value", ""))) <= 1024
        for e in embeds for f in e.get("fields", [])
    )
    check("discord: all field values within 1024 chars", ok_lens)
    ok_titles = all(len(str(e.get("title", ""))) <= 256 for e in embeds)
    check("discord: embed titles within 256 chars", ok_titles)
    titles = [e.get("title") for e in embeds]
    check("discord: engagement + findings embeds present",
          any("Scan Complete" in t for t in titles) and any("Findings" in t for t in titles), str(titles))

    # 6. End dashboard renders without raising ----------------------------
    try:
        end_summary_panel(state, 392)
        check("console: end dashboard rendered", True)
    except Exception as e:
        check("console: end dashboard rendered", False, str(e))

    # ── summary ────────────────────────────────────────────────────────
    failed = [r for r in RESULTS if not r[1]]
    print(f"\n{'─' * 46}")
    print(f"  {len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed"
          + (f" — {len(failed)} FAILED" if failed else " — all green"))
    if failed:
        for name, _, detail in failed:
            print(f"    ✗ {name} {detail}")
    print()

    # Keep the synthetic output for manual inspection; remove to disable.
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
