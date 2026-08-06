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

[*] Target     : 10.10.11.1 (ip)
[*] Profile    : normal
[*] Output dir : ~/rvr_loot/10.10.11.1

── Phase 2 — Network Sweep ──────────────────────────
  ✓  Nmap scan complete (12s)

── Phase 3 — Conditional Enumeration ────────────────
[*] Triggered modules: web, smb
  ✓  ffuf directory fuzzing (34s)
  ✓  Nuclei vulnerability scan (61s)
  ✓  enum4linux-ng full SMB enumeration (9s)

── Phase 4 — AI Analysis ────────────────────────────
  ✓  Gemini CVE correlation complete

── Phase 5 — Report Generation ──────────────────────
  ✓  PDF report saved to ~/rvr_loot/10.10.11.1/report.pdf
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
all share one piece of state (`RVRState`) for the duration of a scan.

```
rvr/
├── core.py                 # Orchestrator — decides which phases run and in what order
├── config/
│   └── config.yaml         # Wordlists, tool binary names, per-profile scan flags
├── modules/
│   ├── base.py              # Shared subprocess runner used by every module
│   ├── network.py           # Nmap sweep (TCP + optional UDP)
│   ├── web.py                # WhatWeb, ffuf, Gobuster, Nuclei
│   ├── smb.py                # enum4linux-ng, NetExec
│   ├── nfs.py                # showmount / NFS enumeration
│   ├── snmp.py               # snmpwalk enumeration
│   ├── osint.py              # subfinder / theHarvester for domain targets
│   └── ai_analysis.py        # Gemini API — CVE correlation over the collected findings
├── output/
│   ├── pdf_report.py         # Builds the final PDF engagement report (reportlab)
│   └── discord_notify.py     # Posts a scan-complete summary to a Discord webhook
└── utils/
    ├── state.py               # RVRState dataclass — the single source of truth for a scan
    ├── console.py              # rich-based logging/formatting helpers
    ├── validator.py            # Target validation (IP / subnet / domain)
    └── network_info.py         # Detects the attacker's VPN (tun0) or LAN interface
```

### The scan pipeline (`run_full`)

`RVRCore.run_full()` walks through six phases, each gated by what's already been
discovered:

1. **OSINT** — only runs if the target is a domain (subfinder / theHarvester).
2. **Network Sweep** — always runs. Nmap TCP scan (optionally UDP with `--udp`), scaled
   by the selected profile (`stealth` / `normal` / `aggressive`). This phase populates
   `RVRState.open_ports`, which drives everything downstream.
3. **Conditional Enumeration** — inspects `open_ports` and launches only the modules
   that apply, in parallel via a `ThreadPoolExecutor`:
   - any web port (80/443/8080/8443/...) → **Web module** (WhatWeb → ffuf → Gobuster →
     Nuclei)
   - 139 or 445 open → **SMB module** (enum4linux-ng → NetExec anonymous/share checks)
   - 111 or 2049 open → **NFS module** (showmount, mount enumeration)
   - 161 open → **SNMP module** (snmpwalk)
4. **AI Analysis** — sends the structured findings (open ports, web tech stack, Nuclei
   hits) to Gemini, which correlates them against known CVE patterns and suggests
   likely attack paths. Skipped automatically if `GEMINI_API_KEY` isn't set.
5. **Report Generation** — renders everything collected into a PDF engagement report.
6. **Discord Notification** — optional webhook ping when the scan finishes, so a scan
   left running against a bigger subnet doesn't need to be babysat.

Every phase writes into the same `RVRState` object and is wrapped in its own
try/except, so one module failing (a tool timing out, a binary not being installed)
doesn't take down the rest of the scan — it's logged and marked failed in the final
state file instead.

### Scan profiles

Profiles are defined once in `core.py` / `config.yaml` and control both Nmap timing and
ffuf request rate:

| Profile | Nmap | ffuf rate |
|---|---|---|
| `stealth` | `-sS --scan-delay 2s`, timing `T1` | 10 req/s |
| `normal` (default) | `-sS -sV -sC`, timing `T3` | 100 req/s |
| `aggressive` | `-sS -sV -sC -A`, timing `T4` | 500 req/s |

### Micro-variant mode

Sometimes you don't want the full pipeline — you want to re-run one tool interactively
against a target you've already scanned. `--tool` bypasses `run_full()` entirely and
drops into a single-tool interactive prompt (`run_micro()`), e.g. choosing between a
quick top-1000 Nmap scan, a full 1–65535 sweep, or custom flags, without re-triggering
web/SMB/NFS modules.

## Requirements

RVR orchestrates external tools rather than reimplementing them — it needs these
installed and on `PATH` (all present by default on Kali, or installable individually):

- `nmap`
- `ffuf`, `gobuster`
- `nuclei`, `subfinder` ([ProjectDiscovery](https://github.com/projectdiscovery) toolkit)
- `enum4linux-ng`, `netexec`
- `whatweb`
- `snmpwalk` (net-snmp)
- `showmount` (nfs-common)
- `theHarvester`

Python dependencies (see `requirements.txt`):

```
rich>=13.0.0
python-dotenv>=1.0.0
requests>=2.31.0
reportlab>=4.0.0
google-generativeai>=0.3.0
```

## Setup

```bash
git clone https://github.com/Ryx13/rvr.git
cd rvr
pip install -r requirements.txt
cp .env.example .env
```

Fill in `.env`:

```bash
# Get a free key at https://aistudio.google.com
GEMINI_API_KEY=your_gemini_api_key_here

# Server Settings → Integrations → Webhooks in Discord
DISCORD_WEBHOOK_URL=your_discord_webhook_url_here
```

Both are optional — omit `GEMINI_API_KEY` and the AI analysis phase is skipped
automatically; omit `DISCORD_WEBHOOK_URL` or pass `--no-discord` and the notification
step is skipped.

If you're targeting a HackTheBox/TryHackMe box, connect your OpenVPN first — RVR
auto-detects your `tun0` (falling back to your primary LAN interface) and prints the
attacker IP it found at startup, so you know immediately if the VPN isn't up.

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

# Skip specific phases
python3 main.py -t 10.10.11.1 --skip osint ai

# Custom output directory, thread count, and UDP top-200 scan
python3 main.py -t 10.10.11.1 -o ./loot --threads 8 --udp
```

Optionally symlink it onto your `PATH` for the `rvr` shorthand used above:

```bash
sudo ln -s "$(pwd)/main.py" /usr/local/bin/rvr
```

### All flags

| Flag | Description |
|---|---|
| `-t, --target` | Target IP, subnet, or domain (required) |
| `--profile` | `stealth` \| `normal` \| `aggressive` (default: `normal`) |
| `--tool` | Run a single tool in interactive micro-variant mode |
| `-o, --output` | Override output directory (default: `~/rvr_loot/<target>`) |
| `--skip` | Skip specific modules: `osint network web smb nfs snmp ai report` |
| `--no-ai` | Disable Gemini AI analysis |
| `--no-discord` | Disable the Discord webhook notification |
| `--no-report` | Skip PDF report generation |
| `--ports` | Override the Nmap port range, e.g. `--ports 1-65535` |
| `--udp` | Include a UDP scan (top 200 ports) |
| `--threads` | Max concurrent threads for conditional modules (default: 4) |
| `-v, --verbose` | Print every underlying command as it runs |

## Output

Everything from a scan lands under `~/rvr_loot/<target>/` (or `-o <dir>`):

```
~/rvr_loot/10.10.11.1/
├── state.json          # Full structured scan state — every finding, machine-readable
├── report.pdf           # Human-readable PDF engagement report
├── network/              # Raw Nmap output
├── web/                  # WhatWeb / ffuf / Gobuster / Nuclei output
├── smb/                  # enum4linux-ng / NetExec output
├── nfs/
└── snmp/
```

`state.json` is the same object every module reads and writes to during the scan —
useful if you want to script something against the raw findings rather than parse the
PDF.

## Design notes

A few decisions worth flagging if you're reading the source:

- **Everything shares one dataclass.** `RVRState` is the single source of truth for a
  scan — every module reads what it needs from it and appends its findings back onto
  it. This is what makes the conditional triggering possible: the web module doesn't
  need to know how ports were discovered; it just checks `state.get_web_ports()`.
- **Modules fail independently.** Each phase is wrapped individually in `RVRCore`, so a
  single tool timing out or not being installed doesn't abort the whole scan — it's
  logged, marked failed in `state.json`, and the rest of the pipeline continues.
- **The AI phase is additive, not load-bearing.** RVR produces a complete, useful PDF
  report from tool output alone; Gemini correlation is an extra layer on top for
  suggested CVEs and attack paths, not a dependency the rest of the tool needs to
  function.

## Disclaimer

Built for authorized penetration testing and CTF/lab environments only. Do not run
this against systems you do not have explicit permission to test.

## Author

Ryan Dube — [ryxvoid.xyz](https://ryxvoid.xyz) · [linkedin.com/in/ryxvoid](https://linkedin.com/in/ryxvoid)
