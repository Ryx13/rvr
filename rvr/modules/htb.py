"""
RVR — HTB / CPTS workflow helpers
Quality-of-life automation for HackTheBox machines, CTF boxes, and CPTS-style
engagements:

  * Hostname discovery — aggregates machine names leaked by SSL cert SAN/CN,
    RDP NTLM info, SMB, LDAP, and NSE script output into one confident value.
  * /etc/hosts entry — `--htb` writes "<ip>  <hostname>" (sudo) so the box
    resolves by name for the rest of the engagement.
  * Machine notes template — a pre-filled notes.md scratchpad (ports, creds
    found, hashes, next steps) supporting the "document in real time" rule
    that decides CPTS passes.
  * Pivot command generator — interactive Ligolo-ng / Chisel / proxychains
    command builder for multi-hop pivoting (CPTS: pivoting is the backbone
    of lateral movement).

None of this fires tools at the target beyond what other modules already
ran — it's pure post-processing of collected state.
"""

import re
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional

from rich.prompt import Prompt, Confirm

from rvr.modules.base import BaseModule
from rvr.utils.console import log_info, log_success, log_warn, console
from rvr.utils.state import RVRState


class HTBModule(BaseModule):
    def __init__(self, state: RVRState, profile: Dict[str, Any]):
        super().__init__(state, profile)

    # ── Hostname aggregation ─────────────────────────────────────
    def detect_hostname(self) -> Optional[str]:
        """Pull machine hostname candidates from every source collected so
        far, pick the most-confirmed one, and record it in state."""
        candidates: Dict[str, List[str]] = {}

        def add(name: Optional[str], source: str):
            if not name:
                return
            name = name.strip().strip(".").lower()
            if len(name) < 3 or name in ("localhost", "unspecified"):
                return
            candidates.setdefault(name, []).append(source)

        for cert in self.state.ssl_certs:
            for san in cert.get("san", []) or []:
                add(san.split(".")[0] if san.count(".") <= 1 else san, "ssl-cert-san")
            add(cert.get("cn"), "ssl-cert-cn")

        rdp = self.state.rdp_findings
        add(rdp.get("dns_computer"), "rdp-ntlm")
        add(rdp.get("netbios_computer"), "rdp-ntlm")

        ldap = self.state.ldap_findings
        if ldap.get("domain"):
            add(str(ldap["domain"]).split(".")[0], "ldap")

        smb = self.state.smb_findings
        smb_domain = smb.get("domain")
        if isinstance(smb_domain, dict):
            add(smb_domain.get("domain"), "smb")
            add(smb_domain.get("server_name") or smb_domain.get("nb_domain"), "smb")

        # nmap script output frequently leaks the NetBIOS/SMB hostname
        for p in self.state.open_ports:
            for script_id, out in (p.get("scripts") or {}).items():
                if script_id in ("smb-os-discovery", "smb2-security-mode", "nbstat"):
                    m = re.search(r"NetBIOS computer name:\s*(\S+)", out) or \
                        re.search(r"Domain name:\s*(\S+)", out)
                    if m:
                        add(m.group(1), f"nmap-{script_id}")

        if not candidates:
            return None

        # Rank: most sources agreeing wins; ties prefer ssl/rdp sources
        ranked = sorted(
            candidates.items(),
            key=lambda kv: (-len(set(kv[1])), 0 if any(s.startswith(("ssl", "rdp")) for s in kv[1]) else 1),
        )
        hostname, sources = ranked[0]
        self.state.hostname = hostname
        self.state.hostname_sources = sorted(set(sources))
        return hostname

    # ── /etc/hosts entry ─────────────────────────────────────────
    def add_hosts_entry(self, hostname: Optional[str] = None) -> bool:
        hostname = hostname or self.state.hostname
        if not hostname:
            log_warn("No hostname discovered — nothing to add to /etc/hosts")
            return False
        if self.state.target_type != "ip":
            log_info("Target is not a raw IP — /etc/hosts entry unnecessary")
            return False

        ip = self.state.target
        entry = f"{ip}\t{hostname}"

        try:
            hosts = Path("/etc/hosts").read_text()
            if re.search(rf"^\s*{re.escape(ip)}\s+.*{re.escape(hostname)}", hosts, re.M):
                log_info(f"/etc/hosts already maps {ip} -> {hostname}")
                return True
        except PermissionError:
            pass

        cmd = ["sudo", "sh", "-c", f"printf '%s\\n' '{entry}' >> /etc/hosts"]
        try:
            result = subprocess.run(cmd, timeout=20)
            if result.returncode == 0:
                log_success(f"/etc/hosts: {entry}")
                return True
            log_warn(f"Failed to update /etc/hosts (sudo returned {result.returncode})")
        except Exception as e:
            log_warn(f"Failed to update /etc/hosts: {e}")
        return False

    # ── Machine notes template ───────────────────────────────────
    def generate_notes(self) -> Optional[Path]:
        """Write notes.md — the live scratchpad for the engagement. CPTS
        golden rule #1 is documenting in real time; this gives the operator
        a structured starting point the second recon finishes."""
        s = self.state
        notes_path = s.output_dir / "notes.md"

        ports_table = "\n".join(
            f"| {p['port']}/{p['proto']} | {p['service']} | {(p.get('version') or '')[:60]} |"
            for p in sorted(s.open_ports, key=lambda x: x["port"])
        ) or "| - | - | - |"

        users = s.get_ad_users()
        hashes_lines = "\n".join(
            f"- [{h['type']}] {h['account']} — crack: `{h['crack_cmd']}`"
            for h in s.captured_hashes
        ) or "_None captured yet_"

        exploits_lines = "\n".join(
            f"- Port {m['port']}: {m['title']} (EDB-{m['id']}) — `searchsploit -m {m['id']}`"
            for m in s.exploit_matches[:15]
        ) or "_No public exploits correlated._"

        next_steps = "\n".join(f"- {step}" for step in (s.ai_next_steps or [])[:8]) or \
            "- Review the report.pdf findings and validate manually"

        hostname_line = f"**Hostname:** `{s.hostname}` _(sources: {', '.join(s.hostname_sources)})_" if s.hostname \
            else "**Hostname:** _not discovered_"

        notes_path.write_text(f"""# Engagement Notes — {s.target}

> Auto-generated by RVR · profile `{s.profile}` · started {s.start_time[:19]}
> Rule #1 of CPTS: document in real time. Fill this in as you go.

{hostname_line}

## Attack surface

| Port | Service | Version |
|---|---|---|
{ports_table}

## Accounts / users

{(', '.join(users[:40])) if users else '_None enumerated yet_'}

## Captured hashes

{hashes_lines}

## Public exploits

{exploits_lines}

## Foothold

- [ ] Initial access vector:
- [ ] User flag (`user.txt`) location & capture:

## Privilege escalation

- [ ] Escalation vector:
- [ ] Root flag (`root.txt` / `root.txt` on Windows: `C:\\Windows\\System32\\config\\root.txt`) capture:

## Next steps (from AI analysis)

{next_steps}

## Timeline / commands worth remembering

```
# (paste commands + one-line outcomes as you work)
```
""")
        log_success(f"Notes template: {notes_path}")
        return notes_path

    # ── Pivot command generator (micro / --pivot) ───────────────
    def generate_pivot_commands(self) -> Optional[Path]:
        """Interactive generator for multi-hop pivoting commands. Produces
        Ligolo-ng (primary), Chisel, and ssh -D alternatives plus routing
        notes — nothing executes automatically, the operator stays in
        control of every tunnel."""
        console.print()
        console.print("[bold cyan]Pivot assistant — multi-hop tunnel command generator[/bold cyan]")
        console.print("[dim]Answers only shape the generated commands; nothing is executed.[/dim]")
        console.print()

        default_ip = self.state.attacker_ip or "10.10.14.1"
        pivot_host = Prompt.ask("Pivot host IP (the box you have a shell on)", default=self.state.target)
        listen_port = Prompt.ask("Ligolo proxy listen port", default="11601")
        agent_port = Prompt.ask("Ligolo agent connect port", default="11601")
        new_subnet = Prompt.ask("Newly reachable subnet behind pivot", default="10.10.10.0/24")

        atk_ip = self.state.attacker_ip or default_ip

        doc = f"""# Pivoting — generated command sheet

Target engagement: {self.state.target}
Pivot host: {pivot_host} · new subnet: {new_subnet}
Attacker: {atk_ip}

## Ligolo-ng (recommended — interface-level routing, fast Nmap through tunnel)

```bash
# 1. On attacker (proxy):
ip tuntap add user $(whoami) mode tun ligolo
ip link set ligolo up
ligolo-proxy -selfcert -listen 0.0.0.0:{listen_port}

# 2. On the pivot host (agent) — upload ligolo-ng agent first:
ligolo-agent -connect {atk_ip}:{agent_port} -ignore-cert -retry

# 3. Back on attacker: route the new subnet through ligolo
ip route add {new_subnet} dev ligolo

# 4. Verify
nmap -sn {new_subnet}            # should now see hosts behind the pivot
```

## Chisel alternative (HTTP/WebSocket tunnel)

```bash
# Attacker:
chisel server -p 8000 --reverse

# Pivot host:
chisel client {atk_ip}:8000 R:socks

# Then use proxychains for tools without native SOCKS support:
proxychains nmap -sT -Pn -p 80,443,445 {new_subnet.split('/')[0]}
```

## SSH dynamic SOCKS alternative (if SSH access exists on pivot)

```bash
ssh -D 1080 user@{pivot_host}
# then: proxychains <tool>
```

## Notes
- Ligolo needs `ip tuntap` permissions (run as regular user with tun access).
- Full port scans through the tunnel: `nmap -p- --min-rate 1000 -iL hosts.txt`
- Every additional subnet behind the next hop repeats step 3 with a new `ip route add`.
"""
        out = self.state.output_dir / "pivoting.md"
        out.write_text(doc)
        log_success(f"Pivot command sheet: {out}")
        return out

    # ── Orchestrated --htb flow ──────────────────────────────────
    def run_htb_flow(self, interactive: bool = True):
        """Post-Phase-3 helper: detect hostname, optionally add /etc/hosts
        entry (interactive confirmation), and generate notes.md."""
        hostname = self.detect_hostname()
        if hostname:
            log_success(f"Machine hostname: [bold]{hostname}[/bold] "
                        f"[dim]({', '.join(self.state.hostname_sources)})[/dim]")
        else:
            log_info("No hostname leaked by any service")

        if hostname and self.config.htb.get("add_hosts_entry", True):
            if interactive:
                if Confirm.ask(f"Add '{self.state.target}  {hostname}' to /etc/hosts?", default=True):
                    self.add_hosts_entry(hostname)
            else:
                self.add_hosts_entry(hostname)

        if self.config.htb.get("generate_notes", True):
            self.generate_notes()
