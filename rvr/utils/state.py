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

    # RDP results
    rdp_findings: Dict[str, Any] = field(default_factory=dict)

    # Web screenshots — [{"url": ..., "path": ...}]
    screenshots: List[Dict[str, str]] = field(default_factory=list)

    # OSINT results (domain targets)
    subdomains: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)

    # AI analysis
    ai_summary: Optional[str] = None
    ai_cves: List[str] = field(default_factory=list)
    ai_vectors: List[str] = field(default_factory=list)

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

    def add_artifact(self, key: str, path: Path):
        """Register an output file"""
        self.artifacts[key] = str(path)

    def mark_complete(self, module: str):
        self.completed_modules.append(module)

    def mark_failed(self, module: str):
        self.failed_modules.append(module)

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
            },
            "network": {
                "open_ports": self.open_ports,
            },
            "web": {
                "findings": self.web_findings,
                "technologies": self.web_technologies,
                "nuclei": self.nuclei_findings,
            },
            "smb": self.smb_findings,
            "nfs": {"mounts": self.nfs_mounts},
            "snmp": self.snmp_data,
            "ftp": self.ftp_findings,
            "databases": self.database_findings,
            "ldap": self.ldap_findings,
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