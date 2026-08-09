# RVR — Ryxvoid Recon Framework

RVR is a Python CLI reconnaissance framework built around one idea: don't run every tool
against every target. Most recon scripts fire off Nmap, ffuf, enum4linux, and a dozen
other tools in parallel regardless of what's actually on the box. RVR runs an initial
sweep, looks at what's actually open, and only launches the modules that make sense for
that specific target — SMB tools only fire if 445 is open, web fuzzing only fires if
there's a web server, and so on.

It's built for authorized penetration testing, CTF environments (HackTheBox,
TryHackMe), and personal lab infrastructure.

```
$ rvr -t 10.10.11.1

╭─────────────────────────────── Scan Plan ────────────────────────────────╮
│      Target  10.10.11.1 (ip)                                             │
│     Profile  normal                                                      │
│              Balanced default — T3 timing, standard -sV -sC service      │
│              detection, 100 req/s fuzzing.                               │
│      Output  ~/rvr_loot/10.10.11.1                                       │
│     Threads  4 concurrent module(s) in Phase 3                           │
│ Attacker IP  10.10.14.5 (tun0)                                           │
╰────────────────────────────────────────────────────────────────────────╯

── Phase 2 — Network Sweep ──────────────────────────
  ✓  Port discovery — 4 open ports (11s)
  ✓  Service detection complete (9s)

── Phase 3 — Conditional Enumeration ────────────────
  Module     Triggered because
  ─────────────────────────────────────────
  web        Any common web port open
  smb        SMB ports 139/445 open
  ftp        FTP port 21 open

  ⠋ Conditional enumeration ━━━━━━━━━━━━━━━━━━━━━━ 3/3  0:00:47

── Phase 4 — AI Analysis ────────────────────────────
  ✓  Risk level: High

── Phase 5 — Report Generation ──────────────────────
  ✓  Report saved: ~/rvr_loot/10.10.11.1/report.pdf

╭──────────────────── Scan Complete — 1m 34s ─────────────────────╮
│  Open ports               4                                     │
│  Web findings              23                                   │
│  Vulnerabilities (Nuclei)  2                                    │
│  AI risk assessment        High                                 │
│  Raw data                  ~/rvr_loot/10.10.11.1/raw_data.json  │
│  Report                    ~/rvr_loot/10.10.11.1/report.pdf     │
╰──────────────────────────────────────────────────────────────────╯
```

## Why it exists

Every recon framework I'd used before either ran a fixed pipeline regardless of the
target, or required me to manually chain tools together myself, re-reading Nmap output
to decide what to run next. RVR automates that decision-making: the network sweep
populates a shared state object, and the orchestrator inspects that state to decide
which modules actually apply. On a target with only SSH open, RVR runs the network
sweep and stops there — no wasted ffuf runs against a port that was never open in the
first place.

## Architecture

RVR is organized as a small orchestrator (`RVRCore`) driving independent modules that
all share one piece of state (`RVRState`) for the duration of a scan. Which conditional
modules exist, and what triggers each one, is declared once in a registry rather than
hardcoded into the orchestrator's control flow.

```
rvr/
├── core.py                    # Orchestrator — decides which phases run and in what order
├── config/
│   └── config.yaml            # Wordlists, tool binary names, per-profile scan flags
├── modules/
│   ├── base.py                 # Shared subprocess runner + config-driven tool() resolver
│   ├── registry.py             # Declares each conditional module's trigger condition
│   ├── network.py              # Nmap sweep (TCP + optional UDP)
│   ├── web.py                   # WhatWeb, ffuf, Gobuster, Nuclei, gowitness screenshots
│   ├── smb.py                   # enum4linux-ng, NetExec
│   ├── nfs.py                   # showmount / RPC enumeration
│   ├── snmp.py                  # snmpwalk enumeration
│   ├── ftp.py                   # Anonymous login check, banner grab, directory listing
│   ├── databases.py             # MySQL/MSSQL/PostgreSQL/Redis/MongoDB misconfig checks
│   ├── ldap_enum.py             # Anonymous LDAP bind + Active Directory enumeration
│   ├── rdp.py                   # Unauth NTLM info leak, NLA/encryption check
│   ├── osint.py                 # subfinder / theHarvester for domain targets
│   ├── ai_analysis.py           # Sends findings to an AI provider for CVE correlation
│   └── ai_providers.py          # Gemini / Groq / Claude / OpenAI provider abstraction
├── output/
│   ├── pdf_report.py            # Builds the final PDF engagement report (reportlab)
│   └── discord_notify.py        # Posts a scan-complete summary to a Discord webhook
└── utils/
    ├── state.py                  # RVRState dataclass — the single source of truth for a scan
    ├── config.py                  # Loads config.yaml, merges over built-in defaults
    ├── console.py                  # rich-based logging, panels, and progress display
    ├── validator.py                # Target validation (IP / subnet / domain)
    └── network_info.py             # Detects the attacker's VPN (tun0) or LAN interface
```

### The scan pipeline (`run_full`)

`RVRCore.run_full()` walks through six phases, each gated by what's already been
discovered:

1. **OSINT** — only runs if the target is a domain (subfinder / theHarvester).
2. **Network Sweep** — always runs. Nmap TCP scan (optionally UDP with `--udp`), scaled
   by the selected profile (`stealth` / `normal` / `aggressive`). This phase populates
   `RVRState.open_ports`, which drives everything downstream.
3. **Conditional Enumeration** — inspects `open_ports` against the module registry and
   launches only what applies, in parallel via a `ThreadPoolExecutor`, with a live
   progress bar tracking overall completion:

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

   Adding a new conditional module means adding one entry to `rvr/modules/registry.py`
   — the orchestrator doesn't need to change.
4. **AI Analysis** — sends the structured findings (open ports, web tech stack, Nuclei
   hits, and now FTP/database/LDAP/RDP findings too) to an AI provider, which correlates
   them against known CVE patterns and suggests likely attack paths. Supports Gemini,
   Groq, Claude, and OpenAI — see [AI providers](#ai-providers) below. Skipped
   automatically if no provider API key is set.
5. **Report Generation** — renders everything collected into a PDF engagement report.
   Always regenerates even when resuming a scan, so it reflects whatever's actually in
   state.
6. **Discord Notification** — optional webhook ping when the scan finishes, so a scan
   left running against a bigger subnet doesn't need to be babysat.

Every phase writes into the same `RVRState` object and is wrapped in its own
try/except, so one module failing (a tool timing out, a binary not being installed)
doesn't take down the rest of the scan — it's logged and marked failed in the final
state file instead.

### Scan profiles

Profiles are defined in `config.yaml` (falling back to built-in defaults if the file is
missing or a profile isn't defined there) and control both Nmap timing and ffuf request
rate:

| Profile | Nmap | ffuf rate |
|---|---|---|
| `stealth` | `-sS --scan-delay 2s`, timing `T1` | 10 req/s |
| `normal` (default) | `-sS -sV -sC`, timing `T3` | 100 req/s |
| `aggressive` | `-sS -sV -sC -A`, timing `T4` | 500 req/s |

### AI providers

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
choice, and `AI_MODEL` to override the default model for whichever provider is
selected.

### Configuration (`config.yaml`)

`rvr/config/config.yaml` controls wordlist paths, tool binary names, per-profile scan
flags, concurrency, and the default output directory. Every module resolves its tool
binary through `self.tool("key")` rather than hardcoding it, so renaming or relocating a
binary (e.g. if `enum4linux-ng` is installed under a different name) is a one-line config
change, not a code change.

A missing, partial, or malformed `config.yaml` never breaks a scan — RVR merges whatever
the file provides over built-in defaults and logs a warning for anything it had to fall
back on. Override which file gets loaded with `--config PATH` or the `RVR_CONFIG`
environment variable.

### Checkpoint / resume

`--resume` re-reads a previous scan's `raw_data.json` from the output directory and
skips any module that already completed successfully, instead of re-running the whole
pipeline from scratch. Useful if a scan died partway through (tool crash, target went
offline, you Ctrl+C'd it) — rerun the same command with `--resume` added and only what's
missing or previously failed actually runs. A module that failed last time and succeeds
on retry moves cleanly out of the failed list. Report generation always re-runs on
resume so the PDF reflects whatever's actually in state, even if new modules completed
this time; AI analysis stays skippable so you're not burning API quota re-analyzing data
you already have.

### Micro-variant mode

Sometimes you don't want the full pipeline — you want to re-run one tool interactively
against a target you've already scanned. `--tool` bypasses `run_full()` entirely and
drops into a single-tool interactive prompt (`run_micro()`) with validated menu choices,
without re-triggering the rest of the pipeline. Covers `nmap`, `ffuf`, `subfinder`,
`nuclei`, `whatweb`, `enum4linux`, `netexec`, `snmpwalk`, `ftp`, `ldapsearch`, and `rdp`
— run `rvr --tool <name> -t <target>` or see `rvr -h` for what each one does.

## Requirements

RVR orchestrates external tools rather than reimplementing them — it needs these
installed and on `PATH` (all present by default on Kali, or installable individually):

- `nmap`
- `ffuf`, `gobuster`
- `nuclei`, `subfinder` ([ProjectDiscovery](https://github.com/projectdiscovery) toolkit)
- `enum4linux-ng`, `netexec`
- `whatweb`
- `snmpwalk` (net-snmp)
- `showmount`, `rpcinfo` (nfs-common / rpcbind)
- `theHarvester`
- `gowitness` (web screenshots)
- `ldapsearch` (ldap-utils / openldap-clients)

FTP enumeration uses Python's stdlib `ftplib` — no extra binary needed. Database and RDP
checks reuse `nmap` (targeted NSE scripts) and `netexec` — nothing new to install there
either.

Python dependencies (see `requirements.txt`):

```
rich>=13.0.0
python-dotenv>=1.0.0
requests>=2.31.0
reportlab>=4.0.0
PyYAML>=6.0

# AI providers — install whichever you plan to use
google-genai>=0.3.0
openai>=1.50.0        # also covers Groq — same client, different base_url
# anthropic>=0.40.0
```

## Setup

```bash
git clone https://github.com/Ryx13/rvr.git
cd rvr
pip install -r requirements.txt
cp .env.example .env
```

Fill in `.env` with whichever AI provider key(s) you have — see
[AI providers](#ai-providers) above — plus, optionally:

```bash
# Server Settings → Integrations → Webhooks in Discord
DISCORD_WEBHOOK_URL=your_discord_webhook_url_here
```

Both are optional — omit every AI provider key and the AI analysis phase is skipped
automatically; omit `DISCORD_WEBHOOK_URL` or pass `--no-discord` and the notification
step is skipped.

If you're targeting a HackTheBox/TryHackMe box, connect your OpenVPN first — RVR
auto-detects your `tun0` (falling back to your primary LAN interface) and shows the
attacker IP it found in the startup panel, so you know immediately if the VPN isn't up.

## Usage

```bash
# Full suite, default (normal) profile
python3 main.py -t 10.10.11.1

# Stealthier timing for environments where noise matters
python3 main.py -t 10.10.11.1 --profile stealth

# Everything, harder — aggressive Nmap flags + high ffuf rate
python3 main.py -t 10.10.11.1 --profile aggressive

# Domain target — runs the OSINT phase (subfinder/theHarvester) first
python3 main.py -t example.com --profile normal

# Just one tool, interactively
python3 main.py --tool nmap -t 10.10.11.1
python3 main.py --tool ffuf -t 10.10.11.1
python3 main.py --tool enum4linux -t 10.10.11.1
python3 main.py --tool ftp -t 10.10.11.1
python3 main.py --tool ldapsearch -t 10.10.11.1
python3 main.py --tool rdp -t 10.10.11.1

# Skip specific phases
python3 main.py -t 10.10.11.1 --skip osint ai

# Resume a scan that died partway through
python3 main.py -t 10.10.11.1 --resume

# Custom config, output directory, thread count, and UDP top-200 scan
python3 main.py -t 10.10.11.1 --config ./my.yaml -o ./loot --threads 8 --udp
```

Optionally symlink it onto your `PATH` for the `rvr` shorthand used above:

```bash
sudo ln -s "$(pwd)/main.py" /usr/local/bin/rvr
```

Run `rvr -h` for the full flag reference, including a breakdown of what every
`--tool` and `--skip` value does.

### All flags

| Flag | Description |
|---|---|
| `-t, --target` | Target IP, subnet, or domain (required) |
| `--profile` | `stealth` \| `normal` \| `aggressive` (default: `normal`) |
| `--tool` | Run a single tool interactively — `nmap`, `ffuf`, `subfinder`, `nuclei`, `whatweb`, `enum4linux`, `netexec`, `snmpwalk`, `ftp`, `ldapsearch`, `rdp` |
| `-o, --output` | Override output directory (default: `<config output.base_dir>/<target>`, normally `~/rvr_loot/<target>`) |
| `--config` | Path to a `config.yaml` to use instead of the bundled default (`RVR_CONFIG` env var also works) |
| `--skip` | Skip specific modules: `osint network web smb nfs snmp ftp databases ldap rdp ai report` |
| `--no-ai` | Disable AI analysis (all providers) |
| `--no-discord` | Disable the Discord webhook notification |
| `--no-report` | Skip PDF report generation |
| `--resume` | Resume a previous scan in the output directory, skipping modules that already completed |
| `--ports` | Override the Nmap port range, e.g. `--ports 1-65535` |
| `--udp` | Include a UDP scan (top 200 ports) |
| `--threads` | Max concurrent threads for Phase 3 (default: `config.yaml`'s `concurrency.max_workers`, normally 4) |
| `-v, --verbose` | Print every underlying command as it runs |

## Output

Everything from a scan lands under `~/rvr_loot/<target>/` (or `-o <dir>`):

```
~/rvr_loot/10.10.11.1/
├── raw_data.json        # Full structured scan state — every finding, machine-readable
├── ai_analysis.json      # Raw AI provider response, if the AI phase ran
├── report.pdf             # Human-readable PDF engagement report
├── network/                 # Raw Nmap output
├── web/                       # WhatWeb / ffuf / Gobuster / Nuclei output
│   └── screenshots/             # gowitness screenshots of discovered web ports
├── smb/                       # enum4linux-ng / NetExec output
├── nfs/
├── snmp/
├── ftp/                        # Banner + anonymous-login enumeration output
├── databases/                  # Per-service nmap NSE output (MySQL/MSSQL/Redis/MongoDB)
├── ldap/                       # RootDSE + anonymous-bind enumeration output
└── rdp/                        # NTLM info + NLA/encryption check output
```

`raw_data.json` is the same object every module reads and writes to during the scan —
useful if you want to script something against the raw findings rather than parse the
PDF, and it's what `--resume` reads back in to figure out what's already done.

## Design notes

A few decisions worth flagging if you're reading the source:

- **Everything shares one dataclass.** `RVRState` is the single source of truth for a
  scan — every module reads what it needs from it and appends its findings back onto
  it. This is what makes the conditional triggering possible: the web module doesn't
  need to know how ports were discovered; it just checks `state.get_web_ports()`.
- **Conditional modules are declared, not hardcoded.** `rvr/modules/registry.py` holds a
  list of `ModuleSpec`s (name, import path, trigger condition, human-readable reason).
  The orchestrator iterates the registry instead of an `if/elif` chain — adding a module
  doesn't mean editing `core.py` in three places.
- **Modules fail independently.** Each phase is wrapped individually in `RVRCore`, so a
  single tool timing out or not being installed doesn't abort the whole scan — it's
  logged, marked failed in `raw_data.json`, and the rest of the pipeline continues.
- **The AI phase is additive, not load-bearing.** RVR produces a complete, useful PDF
  report from tool output alone; AI correlation is an extra layer on top for suggested
  CVEs and attack paths, not a dependency the rest of the tool needs to function — and
  it isn't tied to one vendor, so a quota limit on one provider doesn't stop the phase
  from working if you've configured another.
- **Console output is thread-safe.** Phase 3 runs several modules concurrently; the
  shared logging helpers are guarded by a lock so concurrent output can't interleave
  mid-line and corrupt the terminal.

## Disclaimer

Built for authorized penetration testing and CTF/lab environments only. Do not run
this against systems you do not have explicit permission to test.

## Author

Ryan Dube — [ryxvoid.xyz](https://ryxvoid.xyz) · [linkedin.com/in/ryxvoid](https://linkedin.com/in/ryxvoid)