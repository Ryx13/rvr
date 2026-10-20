"""
RVR — Findings builder
Converts raw RVRState into a structured, severity-ranked list of report-ready
findings. Two sources feed the list:

  1. Deterministic heuristics — every well-known recon signal (anonymous FTP,
     SMB signing disabled, AS-REP roastable accounts, unauthenticated DBs,
     exposed NFS, Nuclei hits, matched public exploits, ...) becomes a
     finding with curated description / impact / remediation text.
  2. AI analysis output (when available) — merged in with source="ai".

Deterministic findings carry the report on their own — the AI layer enriches
rather than gates the deliverable (same philosophy as the scan pipeline).
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from rvr.utils.state import RVRState

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


@dataclass
class ReportFinding:
    fid: str
    title: str
    severity: str
    category: str
    affected: str
    description: str
    evidence: str
    impact: str
    remediation: str
    references: List[str] = field(default_factory=list)
    reproduction: str = ""
    source: str = "detection"  # "detection" | "ai" | "nuclei"


class FindingsBuilder:
    def __init__(self, state: RVRState):
        self.state = state
        self.findings: List[ReportFinding] = []
        self._counter = 0

    # ── Public API ───────────────────────────────────────────────
    def build(self) -> List[ReportFinding]:
        s = self.state

        self._from_nuclei()
        self._from_ftp(s.ftp_findings)
        self._from_smb(s.smb_findings)
        self._from_ldap(s.ldap_findings)
        self._from_kerberos(s.kerberos_findings)
        self._from_databases(s.database_findings)
        self._from_nfs(s.nfs_mounts)
        self._from_rdp(s.rdp_findings)
        self._from_snmp(s.snmp_data)
        self._from_adcs(s.adcs_findings)
        self._from_exploits(s.exploit_matches)
        self._from_web()
        self._from_ssl(s.ssl_certs)
        self._from_ai()

        self.findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.fid))
        return self.findings

    def counts(self) -> Dict[str, int]:
        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def overall_risk(self) -> str:
        counts = self.counts()
        if counts.get("Critical"):
            return "Critical"
        if counts.get("High"):
            return "High"
        if counts.get("Medium"):
            return "Medium"
        if counts.get("Low"):
            return "Low"
        return "Informational"

    # ── Internals ────────────────────────────────────────────────
    def _add(self, **kwargs) -> None:
        self._counter += 1
        kwargs.setdefault("fid", f"F-{self._counter:03d}")
        kwargs.setdefault("category", "Misconfiguration")
        kwargs.setdefault("affected", self.state.target)
        kwargs.setdefault("references", [])
        self.findings.append(ReportFinding(**kwargs))

    # Nuclei ---------------------------------------------------------------
    def _from_nuclei(self):
        by_sev: Dict[str, List[Dict]] = {}
        for f in self.state.nuclei_findings:
            sev = str(f.get("info", {}).get("severity", "info")).capitalize()
            by_sev.setdefault(sev, []).append(f)

        for sev, group in by_sev.items():
            if sev.lower() in ("critical", "high"):
                for f in group:
                    info = f.get("info", {})
                    self._add(
                        title=f"Nuclei: {info.get('name', f.get('template-id', 'vulnerability'))}",
                        severity=sev,
                        category="Vulnerable Service",
                        affected=f.get("matched-at", self.state.target),
                        description=(
                            f"The Nuclei template `{f.get('template-id', '?')}` matched the target, "
                            f"indicating a known {sev.lower()}-severity exposure: {info.get('name', 'unnamed template')}."
                        ),
                        evidence=f"Template: {f.get('template-id', '?')} · Matched at: {f.get('matched-at', '?')}",
                        impact=info.get("description", "")[:400] or
                               f"A known {sev.lower()}-severity condition is present and remotely detectable.",
                        remediation=(
                            "Patch the affected component to a vendor-fixed version, or apply the vendor's "
                            "mitigation guidance for the matched template. Validate the fix by re-running the "
                            "same Nuclei template."
                        ),
                        references=info.get("reference", []) or [],
                        source="nuclei",
                    )
            elif group:
                self._add(
                    title=f"Nuclei: {len(group)} lower-severity template match(es)",
                    severity="Medium" if sev.lower() == "medium" else "Low",
                    category="Vulnerable Service",
                    affected=self.state.target,
                    description=(
                        f"Nuclei matched {len(group)} template(s) of {sev.lower()} severity: "
                        + ", ".join(f.get("template-id", "?") for f in group[:10])
                        + ("..." if len(group) > 10 else "")
                    ),
                    evidence="\n".join(f"  - [{sev}] {f.get('template-id', '?')} at {f.get('matched-at', '?')}" for f in group[:10]),
                    impact="Individually low-impact exposures that may combine with other weaknesses into a viable attack chain.",
                    remediation="Review each matched template, patch where applicable, and re-run Nuclei to verify closure.",
                    source="nuclei",
                )

    # FTP ------------------------------------------------------------------
    def _from_ftp(self, f: Dict[str, Any]):
        if not f:
            return
        if f.get("anonymous_login"):
            self._add(
                title="Anonymous FTP Access Allowed",
                severity="High",
                category="Weak Authentication",
                affected=f"{self.state.target}:21",
                description=(
                    "The FTP service accepts anonymous (unauthenticated) logins. "
                    + (f"The server banner is `{f.get('banner', 'n/a')}`. " if f.get("banner") else "")
                    + "Any anonymous user can enumerate the service's file layout."
                ),
                evidence=(
                    f"Anonymous login succeeded; "
                    f"{len(f.get('anon_listing', []))} item(s) visible in the default directory."
                ),
                impact=(
                    "Anonymous access can expose backups, configuration files, or credentials left on the "
                    "server, and provides a direct file-exfil/recon channel requiring no authentication."
                ),
                remediation=(
                    "Disable the anonymous account in the FTP server configuration (e.g. "
                    "`anonymous_enable=NO` in vsftpd) and rotate any credentials discovered in accessible files."
                ),
                references=["CWE-284: Improper Access Control"],
            )

    # SMB ------------------------------------------------------------------
    def _from_smb(self, smb: Dict[str, Any]):
        if not smb:
            return
        if smb.get("signing") == "disabled":
            self._add(
                title="SMB Signing Not Required",
                severity="Medium",
                category="Misconfiguration",
                affected=f"{self.state.target}:445",
                description="The SMB service does not require message signing, allowing man-in-the-middle attackers to tamper with or relay authenticated SMB sessions.",
                evidence="NetExec reports SMB signing as disabled.",
                impact="Combined with credential relay tooling, an attacker positioned on the network can intercept and relay SMB authentication to impersonate users against other hosts.",
                remediation="Enforce SMB signing via Group Policy ('Microsoft network server: Digitally sign communications, always') and verify legacy clients support it.",
                references=["CVE-2022-26137 considerations", "CWE-345: Insufficient Verification of Data Authenticity"],
            )
        if smb.get("anonymous_login"):
            self._add(
                title="Anonymous SMB Session Permitted",
                severity="Medium",
                category="Weak Authentication",
                affected=f"{self.state.target}:445",
                description="The host accepts anonymous SMB sessions, exposing share listings and — depending on the configuration — readable share content without credentials.",
                evidence=(f"Anonymous session established; shares visible: "
                          f"{', '.join((smb.get('shares') or [])[:8]) or 'n/a'}"),
                impact="Share enumeration is the first step toward locating sensitive or misconfigured files (backups, scripts with embedded credentials, GPP passwords).",
                remediation="Restrict the anonymous/null session via 'Access this computer from the network' policy and remove NULL-session access to shares.",
                references=["CWE-284: Improper Access Control"],
            )
        if smb.get("spray_hits"):
            self._add(
                title="Valid Credentials Discovered via Password Spray",
                severity="Critical",
                category="Weak Authentication",
                affected=f"{self.state.target}",
                description="Operator-directed password spraying produced valid credentials for one or more accounts.",
                evidence="; ".join(smb["spray_hits"][:5]),
                impact="Valid domain credentials enable lateral movement, Kerberoasting, and authenticated enumeration of every protocol the account can reach.",
                remediation="Rotate the affected credentials immediately, enforce strong password policy, and deploy breached-password blocking.",
                source="detection",
            )

    # LDAP -----------------------------------------------------------------
    def _from_ldap(self, d: Dict[str, Any]):
        if not d:
            return
        if d.get("anonymous_bind"):
            users = d.get("anonymous_users") or []
            self._add(
                title="Anonymous LDAP Bind with Directory Enumeration",
                severity=users and "High" or "Medium",
                category="Weak Authentication",
                affected=f"{self.state.target}:389",
                description=(
                    "The directory service accepts anonymous binds, and the naming context is world-readable. "
                    + (f"{len(users)} account names were enumerated without credentials." if users else "")
                ),
                evidence=(f"RootDSE readable anonymously; naming context: {d.get('default_naming_context', 'n/a')}; "
                          f"sample accounts: {', '.join(users[:10])}" if users else "RootDSE readable anonymously."),
                impact=(
                    "Account enumeration feeds password spraying, Kerberoasting and AS-REP roasting. "
                    "Combined with a weak password policy this routinely leads to full domain compromise."
                ),
                remediation="Disable anonymous LDAP reads (restrict 'everyone' / 'anonymous' from List Contents on the domain partition) and enable LDAP signing / channel binding.",
                references=["CWE-284: Improper Access Control"],
            )

    # Kerberos ---------------------------------------------------------------
    def _from_kerberos(self, k: Dict[str, Any]):
        if not k:
            return
        asrep = k.get("asrep_roast", {})
        if asrep.get("count"):
            accounts = asrep.get("accounts", [])
            self._add(
                title=f"AS-REP Roastable Accounts ({asrep['count']})",
                severity="High",
                category="Weak Authentication",
                affected=f"{self.state.target}:88",
                description=(
                    f"{asrep['count']} user account(s) have Kerberos pre-authentication disabled, allowing "
                    "offline extraction of their password hashes without any credentials."
                ),
                evidence=f"Accounts: {', '.join(accounts[:10])}" + ("..." if len(accounts) > 10 else ""),
                impact=(
                    "The captured AS-REP hashes can be cracked offline at GPU speed. Accounts with disabled "
                    "pre-auth are frequently service accounts with weak, long-lived passwords."
                ),
                remediation="Enable Kerberos pre-authentication on the listed accounts and rotate their passwords; enforce long random passwords or managed service accounts (gMSA) for service principals.",
                references=["CWE-693: Protection Mechanism Failure", "MITRE T1558.004 (AS-REP Roasting)"],
            )
        kerb = k.get("kerberoast", {})
        if kerb.get("count"):
            self._add(
                title=f"Kerberoastable Service Accounts ({kerb['count']})",
                severity="High",
                category="Weak Authentication",
                affected=f"{self.state.target}:88",
                description=(
                    f"{kerb['count']} service account(s) with SPNs had their TGS tickets requested using valid "
                    "credentials, yielding offline-crackable hashes."
                ),
                evidence=f"Service accounts: {', '.join(kerb.get('accounts', [])[:10])}",
                impact="Cracked service-account passwords often grant direct privileged access or lateral movement paths.",
                remediation="Rotate service account passwords to 25+ random characters, prefer gMSA, and monitor event 4769 for RC4-encrypted TGS requests.",
                references=["MITRE T1558.003 (Kerberoasting)"],
            )

    # Databases ---------------------------------------------------------------
    def _from_databases(self, dbs: Dict[str, Any]):
        for name, f in (dbs or {}).items():
            flagged = f.get("empty_password") or f.get("unauthenticated")
            if not flagged:
                continue
            self._add(
                title=f"Unauthenticated {name.capitalize()} Access",
                severity="Critical" if f.get("empty_password") else "High",
                category="Weak Authentication",
                affected=f"{self.state.target}:{f.get('port')}",
                description=(
                    f"The {name} service on port {f.get('port')} is reachable "
                    + ("with an empty root/administrator password." if f.get("empty_password")
                       else "without authentication.")
                ),
                evidence="; ".join(f.get("notes", [])[:3])[:300],
                impact=(
                    "Unauthenticated database access typically means full read/write access to application data, "
                    "stored credentials, and — on misconfigured servers — file system and command execution "
                    "(e.g. via FILE privileges or xp_cmdshell)."
                ),
                remediation=(
                    "Set a strong password on the administrative account (or enable authentication for Redis), "
                    "bind the service to localhost where remote access is unnecessary, and remove dangerous "
                    "privileges from application accounts."
                ),
                references=["CWE-306: Missing Authentication for Critical Function"],
            )

    # NFS ---------------------------------------------------------------------
    def _from_nfs(self, mounts: List[str]):
        if not mounts:
            return
        self._add(
            title=f"Network File System Exports Exposed ({len(mounts)})",
            severity="High",
            category="Misconfiguration",
            affected=f"{self.state.target}:2049",
            description=(
                "The NFS service exports "
                + ", ".join(mounts[:6])
                + ("..." if len(mounts) > 6 else "")
                + " to external clients."
            ),
            evidence="\n".join(f"  {m}" for m in mounts[:10]),
            impact=(
                "World-accessible NFS exports can be mounted without authentication. Files with weak root_squash "
                "settings or world-readable permissions leak data, and no_root_squash exports grant direct root-level file writes."
            ),
            remediation="Restrict exports by IP in /etc/exports, enable root_squash (never no_root_squash), and re-evaluate whether each export needs to be network-exposed at all.",
            references=["CWE-732: Incorrect Permission Assignment for Critical Resource"],
        )

    # RDP ----------------------------------------------------------------------
    def _from_rdp(self, d: Dict[str, Any]):
        if d.get("nla_enabled") is False:
            self._add(
                title="RDP Without Network Level Authentication",
                severity="Medium",
                category="Misconfiguration",
                affected=f"{self.state.target}:3389",
                description="The RDP endpoint accepts connections without Network Level Authentication (NLA).",
                evidence="NetExec reports NLA: False.",
                impact="Pre-auth RDP exposes the login screen to credential-guessing and classic RDP vulnerabilities, and leaks hostname/OS build information to unauthenticated callers.",
                remediation="Enable NLA via Group Policy ('Require user authentication for remote connections...') and patch the RDP service to current vendor levels.",
                references=["CWE-306: Missing Authentication for Critical Function"],
            )

    # SNMP ----------------------------------------------------------------------
    def _from_snmp(self, d: Dict[str, Any]):
        community = (d or {}).get("community")
        if community:
            self._add(
                title=f"SNMP Exposed with Community String '{community}'",
                severity="High",
                category="Weak Authentication",
                affected=f"{self.state.target}:161",
                description=(
                    f"The SNMP service answers walk requests with the default/guessable community string "
                    f"'{community}'."
                ),
                evidence=f"snmpwalk succeeded; system: {d.get('system', 'n/a')}",
                impact="SNMP discloses running processes, routes, installed software, and sometimes credentials or configuration — a full reconnaissance feed for follow-on attacks.",
                remediation="Replace the default community with a long random string (or move to SNMPv3 with auth+privacy), and restrict source IPs in the SNMP ACL.",
                references=["CWE-798: Use of Hard-coded Credentials"],
            )

    # ADCS ----------------------------------------------------------------------
    def _from_adcs(self, a: Dict[str, Any]):
        if not a:
            return
        if a.get("web_enrollment"):
            self._add(
                title="AD CS Web Enrollment Exposed",
                severity="High",
                category="Attack Surface",
                affected=a["web_enrollment"].get("url", self.state.target),
                description="An Active Directory Certificate Services web enrollment endpoint (/certsrv) is reachable by unauthenticated users.",
                evidence=f"HTTP {a['web_enrollment'].get('status')} at {a['web_enrollment'].get('url')}",
                impact="Web enrollment endpoints authenticate via NTLM and are prime relay targets; combined with ESC-class template misconfigurations they can yield domain-administrative certificates.",
                remediation="Disable web enrollment if unused, enable EPA/HTTPS on the endpoint, and review certificate templates for ESC1-ESC8 misconfigurations with Certipy.",
                references=["Mitigating NTLM Relay: AD CS", "CWE-306"],
            )
        vt = a.get("vulnerable_templates")
        if vt:
            escs = " ".join(vt.get("esc_classes", [])) or "see Certipy output"
            self._add(
                title=f"Vulnerable Certificate Templates ({escs})",
                severity="Critical",
                category="Misconfiguration",
                affected=self.state.target,
                description=f"Certipy identified certificate templates vulnerable to privilege escalation: {escs}.",
                evidence="; ".join(vt.get("notes", [])[:3])[:300],
                impact="ESC-class template misconfigurations allow a low-privileged user to request certificates that authenticate as arbitrary users — including Domain Admins — achieving full domain compromise.",
                remediation="Apply Microsoft's hardening guidance for the specific ESC class (manage CA/control access rights, enrollee supplies subject flags, SAN policy), and audit template ownership.",
                references=["AD CS ESC1-ESC15 (Certipy documentation)"],
            )

    # Exploit-DB -------------------------------------------------------------
    def _from_exploits(self, matches: List[Dict[str, Any]]):
        if not matches:
            return
        by_port: Dict[int, List[Dict]] = {}
        for m in matches:
            by_port.setdefault(m["port"], []).append(m)
        for port, group in sorted(by_port.items()):
            has_remote = any(g["type"].lower() == "remote" for g in group)
            self._add(
                title=f"Public Exploit Code Available for Service on Port {port}",
                severity="Medium" if not has_remote else "High",
                category="Vulnerable Service",
                affected=f"{self.state.target}:{port}",
                description=(
                    f"Exploit-DB contains {len(group)} publicly documented exploit(s) matching the service "
                    f"banner on port {port} (query: '{group[0]['query']}'). Availability of weaponized "
                    "public code materially lowers the skill required to compromise this service."
                ),
                evidence="\n".join(f"  EDB-{m['id']}: {m['title']} ({m['type']}, {m['date']})" for m in group[:6]),
                impact="An attacker with access to public exploit code can convert version-level intelligence into remote code execution or authentication bypass with minimal effort.",
                remediation="Confirm the exact deployed version, patch to a vendor-fixed release, and validate that no exploit-specific mitigations are missing.",
                reproduction=f"searchsploit -m {' '.join(m['id'] for m in group[:3])}",
                source="detection",
            )

    # Web ----------------------------------------------------------------------
    def _from_web(self):
        interesting = [f for f in self.state.web_findings if f["status"] in [200, 201]]
        admin_paths = [f for f in interesting if any(
            token in f["url"].lower() for token in ("admin", "login", "dashboard", "console", "manager", "phpmyadmin")
        )]
        if admin_paths:
            self._add(
                title="Administrative Interfaces Exposed",
                severity="Medium",
                category="Attack Surface",
                affected=f"{self.state.target} (web)",
                description=(
                    f"{len(admin_paths)} administration/authentication endpoint(s) are publicly reachable and "
                    "return 200 OK to unauthenticated users."
                ),
                evidence="\n".join(f"  [{f['status']}] {f['url']}" for f in admin_paths[:8]),
                impact="Exposed admin panels are high-value brute-force, credential-stuffing and vulnerability targets — one weak password away from application control.",
                remediation="Restrict administrative interfaces to management networks or VPN, enforce MFA, and verify the panels don't leak version or user information pre-auth.",
                references=["OWASP ASVS V4.2"],
            )
        api_hits = [f for f in interesting if f.get("source") == "api-probe"]
        if api_hits:
            self._add(
                title="API Documentation / Endpoints Exposed",
                severity="Medium" if any("swagger" in f["url"].lower() or "openapi" in f["url"].lower() for f in api_hits) else "Low",
                category="Exposed Data",
                affected=f"{self.state.target} (web)",
                description=(
                    f"{len(api_hits)} API-related endpoint(s) responded to unauthenticated requests "
                    "(Swagger/OpenAPI/GraphQL surfaces discovered during probing)."
                ),
                evidence="\n".join(f"  [{f['status']}] {f['url']}" for f in api_hits[:8]),
                impact="Published API specifications enumerate every endpoint and parameter an attacker needs — removing the discovery phase of an API attack entirely.",
                remediation="Disable documentation endpoints in production, require authentication on the API gateway, and review GraphQL introspection settings.",
            )

    # SSL ----------------------------------------------------------------------
    def _from_ssl(self, certs: List[Dict[str, Any]]):
        for cert in certs:
            issuer = cert.get("issuer", "")
            if "Let's Encrypt" in issuer or "R3" in issuer or "DigiCert" in issuer:
                continue
            sans = cert.get("san", [])
            self._add(
                title="Self-Signed / Untrusted TLS Certificate",
                severity="Low",
                category="Misconfiguration",
                affected=cert.get("url", self.state.target),
                description=(
                    "The TLS endpoint presents a certificate from an untrusted issuer "
                    + (f"(issuer: {issuer}). " if issuer else ". ")
                    + (f"Certificate hostnames: {', '.join(sans[:5])}." if sans else "")
                ),
                evidence=f"Subject: {cert.get('subject', 'n/a')} · Issuer: {issuer or 'n/a'} · Valid until: {cert.get('valid_to', 'n/a')}",
                impact="Clients cannot authenticate the server, enabling man-in-the-middle interception, and certificate hostnames leak internal naming conventions.",
                remediation="Issue certificates from a trusted CA (internal PKI for internal services) and automate renewal.",
            )

    # AI merge ------------------------------------------------------------------
    def _from_ai(self):
        for f in self.state.ai_findings or []:
            sev = str(f.get("severity", "Informational")).capitalize()
            if sev not in SEVERITY_ORDER:
                sev = "Informational"
            self._add(
                title=str(f.get("title", "AI finding")),
                severity=sev,
                category=str(f.get("category", "Analysis")),
                affected=self.state.target,
                description=str(f.get("description", "")),
                evidence=str(f.get("evidence", "")),
                impact=str(f.get("description", ""))[:300],
                remediation=str(f.get("remediation", "See vendor guidance.")),
                references=[f"CVE-{c}" if not str(c).upper().startswith("CVE") else str(c) for c in (f.get("cves") or [])][:5],
                source="ai",
            )
