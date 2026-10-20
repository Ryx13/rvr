"""
RVR — Central state management
Holds all scan data and results throughout the engagement
"""

import json
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, Set, List, Dict, Any


@dataclass
class RVRState:
    # Target info
    target: str
    target_type: str          # "ip", "subnet", "domain"
    profile: str              # "stealth", "normal", "aggressive"
    output_dir: Path

    # Options
    skip: Set[str] = field(default_factory=set)
    verbose: bool = False
    threads: int = 4
    port_override: Optional[str] = None
    attacker_ip: Optional[str] = None
    attacker_iface: Optional[str] = None
    tool: Optional[str] = None
    no_discord: bool = False
    udp_scan: bool = False
    resume: bool = False
    # Opt-in AD credentials "user:pass" (--creds) — unlocks credentialed
    # Kerberoast / BloodHound collection. Password-style attacks never run
    # without explicit operator action.
    ad_credentials: Optional[str] = None
    # --htb: enable HTB machine workflow (hostname -> /etc/hosts, notes.md)
    htb_mode: bool = False

    # Scan results — populated as modules run
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    end_time: Optional[str] = None

    # Network results
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    # e.g. [{"port": 80, "proto": "tcp", "service": "http", "version": "Apache 2.4"}]

    # Web results
    web_findings: List[Dict[str, Any]] = field(default_factory=list)
    # e.g. [{"url": "http://...", "status": 200, "size": 1234, "words": 56}]

    web_technologies: List[str] = field(default_factory=list)
    nuclei_findings: List[Dict[str, Any]] = field(default_factory=list)

    # SMB / AD results
    smb_findings: Dict[str, Any] = field(default_factory=dict)

    # NFS results
    nfs_mounts: List[str] = field(default_factory=list)

    # SNMP results
    snmp_data: Dict[str, Any] = field(default_factory=dict)

    # FTP results
    ftp_findings: Dict[str, Any] = field(default_factory=dict)

    # Database results (mysql/mssql/postgresql/redis/mongodb -> findings dict)
    database_findings: Dict[str, Any] = field(default_factory=dict)

    # LDAP / Active Directory results
    ldap_findings: Dict[str, Any] = field(default_factory=dict)

    # Kerberos attack results (kerbrute / AS-REP / Kerberoast)
    kerberos_findings: Dict[str, Any] = field(default_factory=dict)

    # BloodHound collection results
    bloodhound_findings: Dict[str, Any] = field(default_factory=dict)

    # ADCS / certificate services findings (Certipy)
    adcs_findings: Dict[str, Any] = field(default_factory=dict)

    # Searchsploit matches — [{"service": ..., "port": ..., "id": ..., "title": ..., "path": ...}]
    exploit_matches: List[Dict[str, Any]] = field(default_factory=list)

    # Captured hash material — [{"type": "asrep"|"kerberoast", "account": ..., "hash": ..., "crack_cmd": ...}]
    captured_hashes: List[Dict[str, Any]] = field(default_factory=list)

    # Discovered target hostname (HTB machines expose it via cert SAN / SMB / RDP)
    hostname: Optional[str] = None
    hostname_sources: List[str] = field(default_factory=list)

    # RDP results
    rdp_findings: Dict[str, Any] = field(default_factory=dict)

    # Web screenshots — [{"url": ..., "path": ...}]
    screenshots: List[Dict[str, str]] = field(default_factory=list)

    # SSL/TLS certificates — [{"port": 443, "subject": ..., "issuer": ..., "san": [...], "valid_to": ...}]
    ssl_certs: List[Dict[str, Any]] = field(default_factory=list)

    # Virtual hosts discovered via vHost fuzzing — [{"host": ..., "status": ..., "size": ...}]
    vhosts: List[Dict[str, Any]] = field(default_factory=list)

    # OSINT results (domain targets)
    subdomains: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)

    # AI analysis
    ai_summary: Optional[str] = None
    ai_cves: List[str] = field(default_factory=list)
    ai_vectors: List[str] = field(default_factory=list)
    ai_risk_level: Optional[str] = None
    ai_risk_justification: Optional[str] = None
    ai_manual_validation: List[str] = field(default_factory=list)
    ai_priority_targets: List[str] = field(default_factory=list)
    ai_provider_used: Optional[str] = None
    ai_raw: Dict[str, Any] = field(default_factory=dict)
    # AI v2 structured output — [{"title", "severity", "category", "description", "evidence", "remediation", "cves"}]
    ai_findings: List[Dict[str, Any]] = field(default_factory=list)
    # AI v2 attack paths — [{"name", "mitre", "steps", "prerequisites", "impact"}]
    ai_attack_paths: List[Dict[str, Any]] = field(default_factory=list)
    # AI v2 prioritized next actions
    ai_next_steps: List[str] = field(default_factory=list)

    # Raw tool outputs (stored as file paths)
    artifacts: Dict[str, str] = field(default_factory=dict)
    # e.g. {"nmap_xml": "/path/to/scan.xml", "ffuf_json": "/path/to/ffuf.json"}

    # Module completion tracking
    completed_modules: List[str] = field(default_factory=list)
    failed_modules: List[str] = field(default_factory=list)

    def has_port(self, port: int) -> bool:
        """Check if a specific port is open"""
        return any(p["port"] == port for p in self.open_ports)

    def has_any_port(self, *ports: int) -> bool:
        """Check if any of the given ports are open"""
        open_port_nums = {p["port"] for p in self.open_ports}
        return bool(open_port_nums.intersection(set(ports)))

    def get_open_port_numbers(self) -> List[int]:
        """Return list of open port numbers"""
        return [p["port"] for p in self.open_ports]

    def get_web_ports(self) -> List[int]:
        """Return open web ports"""
        web_port_set = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 
                        8008, 8081, 8090, 8181, 9000, 9090, 9443}
        return [p["port"] for p in self.open_ports
                if p["port"] in web_port_set]

    def looks_like_ad(self) -> bool:
        """Heuristic: does this target expose services that suggest an
        Active Directory environment? (Kerberos, LDAP, or SMB alongside
        a DC-typical port layout)."""
        return self.has_any_port(88, 389, 636, 3268, 3269, 445, 139)

    def get_domain(self) -> Optional[str]:
        """Best-effort AD domain / forest name from everything collected
        so far (LDAP RootDSE, RDP NTLM info, SMB). Used by Kerberos,
        BloodHound, and ADCS modules."""
        for source, key in [
            (self.ldap_findings, "domain"),
            (self.rdp_findings, "dns_domain"),
            (self.rdp_findings, "netbios_domain"),
        ]:
            val = source.get(key)
            if val:
                return str(val).strip()
        smb_domain = self.smb_findings.get("domain")
        if isinstance(smb_domain, dict):
            return str(smb_domain.get("domain") or "").strip() or None
        if smb_domain:
            return str(smb_domain).strip()
        return None

    def get_ad_users(self) -> List[str]:
        """Usernames harvested from any anonymous source so far — feeds
        Kerbrute / AS-REP roasting even when Kerbrute itself isn't installed."""
        users = set()
        users.update(self.smb_findings.get("users", []) or [])
        users.update(self.ldap_findings.get("anonymous_users", []) or [])
        users.update(self.kerberos_findings.get("valid_users", []) or [])
        return sorted(u for u in users if u)

    def add_artifact(self, key: str, path: Path):
        """Register an output file"""
        self.artifacts[key] = str(path)

    def mark_complete(self, module: str):
        if module in self.failed_modules:
            self.failed_modules.remove(module)
        if module not in self.completed_modules:
            self.completed_modules.append(module)

    def mark_failed(self, module: str):
        if module not in self.failed_modules:
            self.failed_modules.append(module)

    def is_complete(self, module: str) -> bool:
        """True if this module already succeeded in a previous run (only meaningful with --resume)"""
        return module in self.completed_modules

    def to_dict(self) -> Dict[str, Any]:
        """Serialise state to dict for JSON output"""
        return {
            "meta": {
                "target": self.target,
                "target_type": self.target_type,
                "profile": self.profile,
                "start_time": self.start_time,
                "end_time": self.end_time,
                "completed_modules": self.completed_modules,
                "failed_modules": self.failed_modules,
                "hostname": self.hostname,
                "ad_credentials": self.ad_credentials,
            },
            "network": {
                "open_ports": self.open_ports,
            },
            "web": {
                "findings": self.web_findings,
                "technologies": self.web_technologies,
                "nuclei": self.nuclei_findings,
                "vhosts": self.vhosts,
                "ssl_certs": self.ssl_certs,
            },
            "smb": self.smb_findings,
            "nfs": {"mounts": self.nfs_mounts},
            "snmp": self.snmp_data,
            "ftp": self.ftp_findings,
            "databases": self.database_findings,
            "ldap": self.ldap_findings,
            "kerberos": self.kerberos_findings,
            "bloodhound": self.bloodhound_findings,
            "adcs": self.adcs_findings,
            "exploits": self.exploit_matches,
            "captured_hashes": self.captured_hashes,
            "hostname": {"name": self.hostname, "sources": self.hostname_sources},
            "rdp": self.rdp_findings,
            "screenshots": self.screenshots,
            "osint": {
                "subdomains": self.subdomains,
                "emails": self.emails,
            },
            "ai": {
                "summary": self.ai_summary,
                "cves": self.ai_cves,
                "vectors": self.ai_vectors,
                "risk_level": self.ai_risk_level,
                "risk_justification": self.ai_risk_justification,
                "manual_validation": self.ai_manual_validation,
                "priority_targets": self.ai_priority_targets,
                "findings": self.ai_findings,
                "attack_paths": self.ai_attack_paths,
                "next_steps": self.ai_next_steps,
                "provider_used": self.ai_provider_used,
                "raw": self.ai_raw,
            },
            "artifacts": self.artifacts,
        }

    def save(self):
        """Write state to raw_data.json"""
        self.end_time = datetime.now().isoformat()
        out = self.output_dir / "raw_data.json"
        with open(out, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
        return out

    @staticmethod
    def load_previous_scan(output_dir: Path) -> Optional[Dict[str, Any]]:
        """Read a prior raw_data.json from output_dir, if one exists. Returns
        None (rather than raising) if there's nothing to resume from, so
        callers can fall back to a normal fresh scan."""
        path = Path(output_dir) / "raw_data.json"
        if not path.exists():
            return None
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            return None

    def hydrate_from_dict(self, data: Dict[str, Any]):
        """Populate this state's results + completion tracking from a
        previously saved raw_data.json, so a --resume run can skip modules
        that already succeeded instead of re-scanning from scratch.
        Current-run options (skip/threads/profile/etc.) are left untouched —
        only scan *results* and completion tracking are restored."""
        meta = data.get("meta", {})
        self.completed_modules = list(meta.get("completed_modules", []))
        self.failed_modules = list(meta.get("failed_modules", []))
        self.hostname = meta.get("hostname", self.hostname)
        self.ad_credentials = meta.get("ad_credentials", self.ad_credentials)

        network = data.get("network", {})
        self.open_ports = network.get("open_ports", self.open_ports)

        web = data.get("web", {})
        self.web_findings = web.get("findings", self.web_findings)
        self.web_technologies = web.get("technologies", self.web_technologies)
        self.nuclei_findings = web.get("nuclei", self.nuclei_findings)
        self.vhosts = web.get("vhosts", self.vhosts)
        self.ssl_certs = web.get("ssl_certs", self.ssl_certs)

        self.smb_findings = data.get("smb", self.smb_findings)
        self.nfs_mounts = data.get("nfs", {}).get("mounts", self.nfs_mounts)
        self.snmp_data = data.get("snmp", self.snmp_data)
        self.ftp_findings = data.get("ftp", self.ftp_findings)
        self.database_findings = data.get("databases", self.database_findings)
        self.ldap_findings = data.get("ldap", self.ldap_findings)
        self.kerberos_findings = data.get("kerberos", self.kerberos_findings)
        self.bloodhound_findings = data.get("bloodhound", self.bloodhound_findings)
        self.adcs_findings = data.get("adcs", self.adcs_findings)
        self.exploit_matches = data.get("exploits", self.exploit_matches)
        self.captured_hashes = data.get("captured_hashes", self.captured_hashes)
        hostname = data.get("hostname", {}) or {}
        self.hostname = hostname.get("name", self.hostname)
        self.hostname_sources = hostname.get("sources", self.hostname_sources)
        self.rdp_findings = data.get("rdp", self.rdp_findings)
        self.screenshots = data.get("screenshots", self.screenshots)

        osint = data.get("osint", {})
        self.subdomains = osint.get("subdomains", self.subdomains)
        self.emails = osint.get("emails", self.emails)

        ai = data.get("ai", {})
        self.ai_summary = ai.get("summary", self.ai_summary)
        self.ai_cves = ai.get("cves", self.ai_cves)
        self.ai_vectors = ai.get("vectors", self.ai_vectors)
        self.ai_risk_level = ai.get("risk_level", self.ai_risk_level)
        self.ai_risk_justification = ai.get("risk_justification", self.ai_risk_justification)
        self.ai_manual_validation = ai.get("manual_validation", self.ai_manual_validation)
        self.ai_priority_targets = ai.get("priority_targets", self.ai_priority_targets)
        self.ai_findings = ai.get("findings", self.ai_findings)
        self.ai_attack_paths = ai.get("attack_paths", self.ai_attack_paths)
        self.ai_next_steps = ai.get("next_steps", self.ai_next_steps)
        self.ai_provider_used = ai.get("provider_used", self.ai_provider_used)
        self.ai_raw = ai.get("raw", self.ai_raw)

        self.artifacts = data.get("artifacts", self.artifacts)