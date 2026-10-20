# RVR — Ryxvoid Recon Framework

```
  ██████╗ ██╗   ██╗██████╗
  ██╔══██╗██║   ██║██╔══██╗
  ██████╔╝██║   ██║██████╔╝
  ██╔══██╗╚██╗ ██╔╝██╔══██╗
  ██║  ██║ ╚████╔╝ ██║  ██║
  ╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝
  RYXVOID RECON FRAMEWORK · v2.0.0 · CPTS / HTB edition
```

RVR is a Python CLI reconnaissance framework built around one idea: **don't run every tool
against every target.** Most recon scripts fire Nmap, ffuf, enum4linux, and a dozen other
tools in parallel regardless of what's actually on the box. RVR runs an initial sweep,
looks at what's actually open, and only launches the modules that make sense for that
specific target — SMB tooling only fires if 445 is open, Kerberos attacks only fire if
88 is open, web fuzzing only fires if there's a web server.

v2 turns that engine into a **CPTS-grade attack-surface mapper**: Active Directory
enumeration (Kerberos attacks, BloodHound collection, ADCS misconfiguration detection),
Exploit-DB correlation, a HTB machine workflow, AI attack-path analysis, and
commercial-grade PDF + Markdown reporting — the kind of deliverable the CPTS exam
grades you on, not just a port list.

Built for authorized penetration testing, HackTheBox machines and CTFs, and personal
lab infrastructure.

```
$ rvr -t 10.10.11.23 --htb

╭────────────────────────── Scan Plan ──────────────────────────╮
│      Mode  FULL PIPELINE — phases 1 → 6                        │
│    Target  10.10.11.23 (ip)                                    │
│   Profile  aggressive                                          │
│  HTB mode  ENABLED — hostname → /etc/hosts → notes.md          │
│ Attacker IP  10.10.14.7 (tun0)                                 │
╰────────────────────────────────────────────────────────────────╯

── Phase 2 — Network Sweep ──────────────────────────────
  ✓  Port discovery — 10 open ports (24s)
  ✓  Service detection complete (31s)

── Phase 3 — Conditional Enumeration ────────────────────
  ✓ Module            Triggered because
  ○ web               Any common web port open
  ○ smb               SMB ports 139/445 open
  ○ ldap              LDAP/AD ports 389/636/3268/3269 open
  ○ kerberos          Kerberos port 88 open — Kerbrute / AS-REP roast
  ○ bloodhound        Kerberos + LDAP open — likely a Domain Controller
  ○ adcs              Web ports + AD services open
  ○ exploits          Services with versions detected — Exploit-DB correlation
  ⠋ Conditional enumeration ━━━━━━━━━━━━━━━━━━━━━ 7/7  0:03:12

── Phase 3.5 — HTB Workflow ─────────────────────────────
  ✓  Machine hostname: dc01.support.htb (ssl-cert-san, rdp-ntlm, smb)
  ✓  /etc/hosts: 10.10.11.23  dc01.support.htb
  ✓  Notes template: ~/rvr_loot/10.10.11.23/notes.md

╭─────────────── Scan Complete — 5m 48s ────────────────────────╮
│        Risk  ■ CRITICAL                                        │
│    Findings  🔴 4  🟠 6  🟡 5  🟢 2  (17 total)                 │
│                                                                │
│  Services   PORT   SERVICE         VERSION                     │
│             88/tcp  kerberos-sec   Microsoft Windows Kerberos  │
│             445/tcp microsoft-ds   Windows Server 2019         │
│             ...                                                │
│  Top findings                                                  │
│    🔴 Nuclei: MySQL Root Empty Password · 10.10.11.23:3306     │
│    🔴 AS-REP Roastable Accounts (2) · 10.10.11.23:88           │
│  Attack intel                                                  │
│    domain support.htb · 2 AS-REP roastable · 1 kerberoastable  │
│    · 2 hash(es) captured · 2 public exploit(s)                 │
│  Deliverables   report.pdf  report.md  notes.md                │
╰────────────────────────────────────────────────────────────────╯
```

## What's new in v2.0.0

| Area | Change |
|---|---|
| **AD attacks** | New modules: `kerberos` (Kerbrute, AS-REP roasting, opt-in Kerberoasting with hashcat command generation), `bloodhound` (anonymous/credentialed collection + manual fallback), `adcs` (web enrollment detection, certipy vulnerable-template enumeration) |
| **Exploit correlation** | `exploits` module runs searchsploit against every identified service+version and feeds matches into reports, AI prompts and notes |
| **Web depth** | SSL certificate mining (SAN/CN → hostnames), virtual host fuzzing, API endpoint discovery, extension fuzzing |
| **HTB workflow** | `--htb` — machine hostname aggregation from every collected source, `/etc/hosts` entry, pre-filled `notes.md` engagement scratchpad; `--tool pivot` generates Ligolo-ng / Chisel / SSH tunnel command sheets |
| **Reports** | Complete rewrite: severity-ranked findings with evidence/impact/remediation, attack paths, remediation roadmap, appendices — rendered to **PDF and Markdown** from the same findings builder, complete with or without AI |
| **Discord** | Multi-embed notification mirroring the report: engagement overview, findings, attack surface, AD intel, AI next steps |
| **AI analysis v2** | Structured findings, MITRE-mapped attack paths, prioritized next-step commands — merged into (not required by) the reports |
| **CLI / install** | `pyproject.toml` with an `rvr` entry point, `rvr/cli.py`, `--htb`, `--creds`, 17 micro-tools, self-healing launcher, resume support for every new module |
| **UI** | New gradient banner, phase-tracked headers, end-of-scan dashboard with services table, severity distribution and attack intel |

## The scan pipeline

`RVRCore.run_full()` walks six phases, each gated by what's already been discovered:

1. **OSINT** — only runs if the target is a domain (subfinder / theHarvester).
2. **Network Sweep** — always runs. Nmap TCP scan (optionally UDP with `--udp`), scaled by
   the selected profile (`stealth` / `normal` / `aggressive`). Populates `RVRState.open_ports`,
   which drives everything downstream.
3. **Conditional Enumeration** — inspects `open_ports` against the module registry and
   launches only what applies, in parallel via a `ThreadPoolExecutor` with a live progress bar:

   | Module | Triggered by |
   |---|---|
   | `web` | Any common web port open (80/443/8080/8443/8000/8888/3000/5000/...) |
   | `smb` | Port 139 or 445 open |
   | `nfs` | Port 111 or 2049 open |
   | `snmp` | Port 161 open |
   | `ftp` | Port 21 open |
   | `databases` | Port 3306 (MySQL), 1433 (MSSQL), 5432 (PostgreSQL), 6379 (Redis), or 27017 (MongoDB) open |
   | `ldap` | Port 389, 636, 3268, or 3269 open |
   | `rdp` | Port 3389 open |
   | `kerberos` | Port 88 open — Kerbrute + AS-REP roasting (Kerberoast is opt-in via `--creds`) |
   | `bloodhound` | Kerberos **and** LDAP open — likely a Domain Controller |
   | `adcs` | Web ports + AD services open — AD CS web enrollment / certipy checks |
   | `exploits` | Any service with a version banner — Exploit-DB correlation |

   Adding a new conditional module means adding one entry to `rvr/modules/registry.py` —
   the orchestrator doesn't need to change.

3.5. **HTB workflow** (`--htb`, IP targets) — aggregates the machine hostname from every
   collected source (SSL SAN/CN, RDP NTLM info, SMB, LDAP, NSE scripts), optionally adds
   it to `/etc/hosts`, and writes a `notes.md` engagement scratchpad.

4. **AI Analysis** — sends the structured findings to an AI provider, which returns
   severity-ranked findings, MITRE-mapped attack paths, and prioritized next-step commands.
   Skipped automatically if no provider API key is set.
5. **Report Generation** — PDF + Markdown engagement reports (details below). Always
   regenerates even when resuming, so it reflects whatever's actually in state.
6. **Discord Notification** — optional rich multi-embed webhook ping when the scan finishes.

Every phase writes into the same `RVRState` object and is wrapped in its own try/except —
one module failing (a tool timing out, a binary not installed) never takes down the scan;
it's logged and marked failed in the final state file instead.

### Credential attacks are opt-in

No credential-style attack ever runs automatically. Unauthenticated checks (anonymous
enumeration, AS-REP roasting) run on their own because they require no credentials.
Everything that *uses* credentials is gated:

- `--creds user:pass` — unlocks Kerberoasting, credentialed BloodHound collection and
  certipy enumeration
- `--tool spray` — interactive password spray with explicit lockout warnings

## Reports

Both report formats are generated from the same **findings builder** — deterministic
heuristics turn every well-known recon signal (anonymous FTP, SMB signing disabled,
AS-REP roastable accounts, unauthenticated databases, exposed NFS, Nuclei hits, matched
public exploits, ...) into a structured finding with curated description, evidence,
impact and remediation text. AI findings are merged in on top. The reports are complete
with or without an AI provider configured — AI enriches, it doesn't gate.

**`report.pdf`** — the client-facing deliverable: cover page, table of contents,
engagement overview with methodology, executive summary, risk summary matrix, detailed
findings (description / evidence / reproduction / impact / remediation / references per
finding), attack-path analysis with MITRE mapping, a prioritized remediation roadmap,
and technical appendices A–H (network, web, directory services, captured hashes,
Exploit-DB correlation, OSINT, screenshots, artifacts).

**`report.md`** — the same structure as portable Markdown: diffs cleanly, lives in git,
pastes into note apps. Adds a *Recommended Next Steps* section with ready-to-run
commands — the document you keep open during the engagement while the PDF is the one
you hand over.

Both carry an overall risk rating, severity distribution (Critical / High / Medium /
Low / Informational), and honour the CPTS rule that the report is the deliverable, not
the flags.

## Discord notifications

With `DISCORD_WEBHOOK_URL` set, scan completion posts a multi-embed summary that mirrors
the report: engagement overview (target, profile, duration, risk), findings with severity
distribution and critical/high detail, attack surface (ports, web stack, vHosts, TLS
certificates), AD / attack intel (domain, roastable accounts, captured hashes, public
exploits), and AI next steps. Disable with `--no-discord`.

## HTB / CPTS workflow

Built around how CPTS-style engagements actually go:

```bash
# Machine workflow: hostname discovery → /etc/hosts → notes.md → full pipeline
rvr -t 10.10.11.23 --htb --profile aggressive

# Found credentials mid-engagement? Re-run with them to unlock Kerberoast,
# credentialed BloodHound and certipy (resume skips what's already done)
rvr -t 10.10.11.23 --creds svc-web:'Summer2024!' --resume

# Multi-hop pivoting (CPTS is built on it) — generates a command sheet for
# Ligolo-ng, Chisel and SSH tunnels; nothing executes automatically
rvr --tool pivot -t 10.10.11.23
```

`notes.md` is pre-filled with the attack surface table, enumerated accounts, captured
hashes with their cracking commands, exploit matches, and foothold / privilege-escalation
checkboxes — because documenting in real time is the difference between passing and
failing the CPTS report even when you have all the flags.

## AI providers

`rvr/modules/ai_providers.py` abstracts over four providers so AI analysis isn't tied to
a single vendor's quota. Set whichever API key(s) you have in `.env`:

| Provider | Env var | Notes |
|---|---|---|
| Gemini | `GEMINI_API_KEY` | Free tier at [aistudio.google.com](https://aistudio.google.com) |
| Groq | `GROQ_API_KEY` | Free tier, no credit card — [console.groq.com/keys](https://console.groq.com/keys) |
| Claude | `ANTHROPIC_API_KEY` | [console.anthropic.com](https://console.anthropic.com) |
| OpenAI | `OPENAI_API_KEY` | [platform.openai.com](https://platform.openai.com) |

With `AI_PROVIDER` unset or `auto`, RVR picks the first available key in the order
above. Set `AI_PROVIDER` explicitly (`gemini` / `groq` / `claude` / `openai`) to force a
choice, and `AI_MODEL` to override the default model.

## Architecture

```
rvr/
├── cli.py                     # CLI entry point (argparse, env validation, sudo pre-auth)
├── core.py                    # Orchestrator — phases, registry-driven dispatch, micro mode
├── config/
│   └── config.yaml            # Wordlists, tool binary names, per-profile scan flags
├── modules/
│   ├── base.py                # Shared subprocess runner + config-driven tool() resolver
│   ├── registry.py            # Declares each conditional module's trigger condition
│   ├── network.py             # Nmap sweep (TCP + optional UDP)
│   ├── web.py                 # WhatWeb, ffuf, Nuclei, gowitness, vHost/API/SSL discovery
│   ├── smb.py                 # enum4linux-ng, NetExec, opt-in password spray
│   ├── kerberos.py            # Kerbrute, AS-REP roast, Kerberoast, hashcat command gen
│   ├── bloodhound.py          # bloodhound-python collection + manual fallback
│   ├── adcs.py                # AD CS web enrollment detection, certipy templates
│   ├── exploits.py            # searchsploit Exploit-DB correlation
│   ├── htb.py                 # Hostname aggregation, /etc/hosts, notes.md, pivot generator
│   ├── ldap_enum.py           # Anonymous LDAP bind + Active Directory enumeration
│   ├── rdp.py                 # Unauth NTLM info leak, NLA/encryption check
│   ├── nfs.py / snmp.py / ftp.py / databases.py / osint.py
│   ├── ai_analysis.py         # Structured AI analysis (findings, attack paths, next steps)
│   └── ai_providers.py        # Gemini / Groq / Claude / OpenAI provider abstraction
├── output/
│   ├── findings.py            # RVRState → severity-ranked report findings
│   ├── pdf_report.py          # Commercial-grade PDF engagement report (reportlab)
│   ├── markdown_report.py     # Markdown twin of the PDF + next-step commands
│   └── discord_notify.py      # Rich multi-embed Discord notification
└── utils/
    ├── state.py               # RVRState dataclass — single source of truth for a scan
    ├── config.py              # Loads config.yaml, merges over built-in defaults
    ├── console.py             # Rich banner, thread-safe logging, end-of-scan dashboard
    ├── validator.py           # Target validation (IP / subnet / domain)
    └── network_info.py        # Detects the attacker's VPN (tun0) or LAN interface
```

`main.py` remains as a thin shim for direct invocation; the packaged `rvr` command
(pyproject.toml) and the global launcher both route through `rvr/cli.py`.

### Scan profiles

| Profile | Nmap | ffuf rate |
|---|---|---|
| `stealth` | `-sS --scan-delay 2s`, timing `T1` | 10 req/s |
| `normal` (default) | `-sS -sV -sC`, timing `T3` | 100 req/s |
| `aggressive` | `-sS -sV -sC -A`, timing `T4` | 500 req/s |

### Configuration (`config.yaml`)

`rvr/config/config.yaml` controls wordlists (including vHost and username lists), tool
binary names, per-profile scan flags, concurrency, and the default output directory.
Every module resolves its tool binary through `self.tool("key")` rather than hardcoding
it, so renaming or relocating a binary is a one-line config change, not a code change.

A missing, partial, or malformed `config.yaml` never breaks a scan — RVR merges whatever
the file provides over built-in defaults and logs a warning for anything it had to fall
back on. Override which file gets loaded with `--config PATH` or the `RVR_CONFIG`
environment variable.

### Checkpoint / resume

`--resume` re-reads a previous scan's `raw_data.json` from the output directory and
skips any module that already completed successfully, instead of re-running the whole
pipeline. Useful if a scan died partway through (tool crash, target went offline, you
Ctrl+C'd it) — rerun the same command with `--resume` added and only what's missing or
previously failed actually runs. Works across the new AD modules too: scan anonymous,
find credentials, re-run with `--creds ... --resume` and only the credentialed
collection runs.

### Micro-variant mode

Sometimes you don't want the full pipeline — you want to re-run one tool interactively
against a target you've already scanned. `--tool` bypasses `run_full()` entirely and
drops into a single-tool interactive prompt with validated menu choices:

`nmap` · `ffuf` · `subfinder` · `nuclei` · `whatweb` · `enum4linux` · `netexec` ·
`snmpwalk` · `ftp` · `ldapsearch` · `rdp` · `kerberos` · `bloodhound` ·
`searchsploit` · `vhosts` · `pivot` · `spray`

```bash
rvr --tool kerberos -t 10.10.11.23    # Kerbrute + AS-REP roast, or Kerberoast
rvr --tool searchsploit -t 10.10.11.23  # correlate state's services against Exploit-DB
rvr --tool vhosts -t 10.10.11.23      # vHost fuzzing on the first web port
```

## Requirements

RVR orchestrates external tools rather than reimplementing them. It needs these
installed and on `PATH` (all present by default on Kali):

- `nmap`, `ffuf`, `gobuster`, `whatweb`, `nuclei`, `subfinder`, `gowitness`
- `enum4linux-ng`, `netexec`
- `snmpwalk` (net-snmp), `showmount` / `rpcinfo` (nfs-common), `ldapsearch` (ldap-utils)
- `theHarvester`
- `searchsploit` (exploitdb)
- `impacket` (`impacket-GetNPUsers`, `impacket-GetUserSPNs` — on Kali these install as
  `/usr/bin/impacket-*`)
- `bloodhound-python` (`pipx install bloodhound-ce` or your package manager)
- `hashcat` / `john` — for the generated cracking commands (optional; commands are
  written either way)
- `kerbrute`, `certipy`, `ligolo-ng` — optional; modules detect their absence, skip, and
  write `MANUAL_COMMANDS.md` files with the exact commands to run instead

Missing tools are warnings, not failures — every module degrades to guidance.

Python dependencies (see `requirements.txt`): `rich`, `python-dotenv`, `requests`,
`reportlab`, `PyYAML`, plus `google-genai` / `openai` (and optionally `anthropic`) for
the AI phase.

## Setup

```bash
git clone https://github.com/Ryx13/rvr.git
cd rvr

python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

cp .env.example .env     # fill in your AI keys / Discord webhook (all optional)
```

Install as a proper command (recommended):

```bash
.venv/bin/pip install -e .     # puts `rvr` on PATH via the package entry point
rvr --version                  # RVR v2.0.0
```

Or run it without installing:

```bash
.venv/bin/python main.py -t 10.10.11.23
.venv/bin/python -m rvr.cli -t 10.10.11.23
```

The dev checkout can also carry a self-healing global launcher at `/usr/local/bin/rvr`
that verifies the venv before every run and rebuilds it if a system Python upgrade
broke it — see the launcher block in this repo's docs or write your own pointing at
`<checkout>/main.py`.

If you're targeting a HackTheBox box, connect your OpenVPN first — RVR auto-detects
your `tun0` (falling back to your primary LAN interface) and shows the attacker IP it
found in the startup panel, so you know immediately if the VPN isn't up.

## Usage

```bash
# Full suite, default (normal) profile
rvr -t 10.10.11.23

# HTB machine: hostname → /etc/hosts → notes.md, loud profile
rvr -t 10.10.11.23 --htb --profile aggressive

# Stealthier timing where noise matters
rvr -t 10.10.11.23 --profile stealth

# Domain target — runs the OSINT phase first
rvr -t example.com

# Credentialed AD collection (also re-runnable with --resume)
rvr -t 10.10.11.23 --creds svc-web:'Summer2024!'

# Just one tool, interactively
rvr --tool nmap -t 10.10.11.23
rvr --tool kerberos -t 10.10.11.23

# Skip phases, resume, custom everything
rvr -t 10.10.11.23 --skip ai exploits
rvr -t 10.10.11.23 --resume
rvr -t 10.10.11.23 --config ./my.yaml -o ./loot --threads 8 --udp
```

Run `rvr -h` for the full flag reference, including a breakdown of what every `--tool`
and `--skip` value does.

### All flags

| Flag | Description |
|---|---|
| `-t, --target` | Target IP, subnet, or domain (required) |
| `--profile` | `stealth` \| `normal` \| `aggressive` (default: `normal`) |
| `--tool` | Run a single tool interactively — 17 tools, see `rvr -h` |
| `--htb` | HTB / CPTS workflow: hostname discovery, `/etc/hosts` entry (asks first), `notes.md` scratchpad |
| `--creds` | AD credentials `USER:PASS` — unlocks Kerberoast, credentialed BloodHound, certipy. Opt-in only |
| `-o, --output` | Override output directory (default: `<config output.base_dir>/<target>`, normally `~/rvr_loot/<target>`) |
| `--config` | Path to a `config.yaml` to use instead of the bundled default (`RVR_CONFIG` env var also works) |
| `--skip` | Skip specific modules: `osint network web smb nfs snmp ftp databases ldap rdp kerberos bloodhound adcs exploits ai report` |
| `--no-ai` | Disable AI analysis (all providers) |
| `--no-discord` | Disable the Discord webhook notification |
| `--no-report` | Skip PDF/Markdown report generation |
| `--resume` | Resume a previous scan in the output directory, skipping modules that already completed |
| `--ports` | Override the Nmap port range, e.g. `--ports 1-65535` |
| `--udp` | Include a UDP scan (top 200 ports) |
| `--threads` | Max concurrent threads for Phase 3 (default: `config.yaml`'s `concurrency.max_workers`, normally 4) |
| `-v, --verbose` | Print every underlying command as it runs |
| `--version` | Print the version |

## Output

Everything from a scan lands under `~/rvr_loot/<target>/` (or `-o <dir>`):

```
~/rvr_loot/10.10.11.23/
├── raw_data.json        # Full structured scan state — every finding, machine-readable
├── ai_analysis.json     # Raw AI provider response, if the AI phase ran
├── report.pdf           # Commercial-grade PDF engagement report
├── report.md            # Markdown twin + recommended next-step commands
├── notes.md             # HTB engagement scratchpad (--htb)
├── network/             # Raw Nmap output
├── web/                 # WhatWeb / ffuf / Nuclei output + screenshots/
├── smb/                 # enum4linux-ng / NetExec output
├── kerberos/            # Kerbrute / AS-REP / Kerberoast hashes + crack_commands.sh
├── bloodhound/          # Collection .zip + MANUAL_COMMANDS.md fallback
├── adcs/                # certipy output / manual commands
├── exploits/            # searchsploit JSON per port
├── nfs/  snmp/  ftp/  databases/  ldap/  rdp/
└── pivoting.md          # Generated tunnel command sheet (--tool pivot)
```

`raw_data.json` is the same object every module reads and writes during the scan —
useful for scripting against the raw findings rather than parsing the PDF, and it's
what `--resume` reads back in to figure out what's already done.

## Testing

A synthetic-state smoke test exercises the findings builder, both report formats, the
Discord payload, HTB notes generation and the end-of-scan dashboard against a rich,
realistic state — without touching any target:

```bash
.venv/bin/python tests/test_synthetic_report.py
```

## Design notes

A few decisions worth flagging if you're reading the source:

- **Everything shares one dataclass.** `RVRState` is the single source of truth for a
  scan — every module reads what it needs from it and appends its findings back onto
  it. This is what makes conditional triggering possible: the web module doesn't need
  to know how ports were discovered; it just checks `state.get_web_ports()`.
- **Conditional modules are declared, not hardcoded.** `rvr/modules/registry.py` holds a
  list of `ModuleSpec`s (name, import path, trigger condition, human-readable reason).
  The orchestrator iterates the registry instead of an `if/elif` chain — adding a module
  doesn't mean editing `core.py` in three places.
- **Modules fail independently.** Each phase is wrapped individually in `RVRCore`, so a
  single tool timing out or not being installed doesn't abort the whole scan — it's
  logged, marked failed in `raw_data.json`, and the rest of the pipeline continues.
- **The AI phase is additive, not load-bearing.** Reports are built from deterministic
  findings first; AI findings, attack paths and next steps merge in on top. No provider
  configured → still a complete deliverable.
- **Credential attacks never run automatically.** Unauthenticated checks only, unless
  the operator passes `--creds` or explicitly invokes `--tool spray` past its warnings.
- **Console output is thread-safe.** Phase 3 runs several modules concurrently; the
  shared logging helpers are guarded by a lock so concurrent output can't interleave
  mid-line and corrupt the terminal.

## Disclaimer

Built for authorized penetration testing and CTF/lab environments only. Do not run
this against systems you do not have explicit permission to test.

## Author

Ryan Dube — [ryxvoid.xyz](https://ryxvoid.xyz) · [linkedin.com/in/ryxvoid](https://linkedin.com/in/ryxvoid)
