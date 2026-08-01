# RVR — Ryxvoid Recon Framework

Automated reconnaissance framework that chains industry-standard tools into a single
conditional pipeline: one target, one command, a structured report at the end.

## What it does

RVR runs an initial scan against a target and uses the results to decide what to run
next — rather than firing every tool at every target regardless of relevance.

- Port 445 open → SMB enumeration (enum4linux-ng, NetExec) fires automatically
- Port 80/443 open → web fuzzing (ffuf, Gobuster) and vulnerability scanning (Nuclei) fire automatically
- Every module result feeds into a Gemini-API-driven analysis pass for CVE correlation
  and suggested attack vectors, cross-referenced against the NVD CVE database
- Findings are compiled into a professional PDF engagement report at the end of the run

## Usage

```bash
rvr -t 10.10.11.1                       # Full suite, normal profile
rvr -t 10.10.11.1 --profile stealth     # Full suite, stealth profile
rvr -t 10.10.11.1 --profile aggressive  # Full suite, aggressive profile
rvr -t example.com --profile normal     # Domain target with OSINT
rvr --tool nmap -t 10.10.11.1           # Micro-variant: nmap only
rvr --tool ffuf -t 10.10.11.1           # Micro-variant: ffuf only
rvr --tool enum4linux -t 10.10.11.1     # Micro-variant: enum4linux only
```

## Key features

- Intelligent conditional chaining — modules trigger based on what earlier modules discover
- Stealth / Normal / Aggressive scan profiles
- Orchestrates Nmap, ffuf, Gobuster, Nuclei, enum4linux-ng, NetExec, and more
- Gemini AI integration for CVE identification and attack-vector analysis
- Discord webhook notifications on scan completion
- Auto-generated PDF engagement reports
- Parallel module execution with noise filtering
- Tested against live HackTheBox machines

## Setup

```bash
git clone https://github.com/Ryx13/rvr.git
cd rvr
pip install -r requirements.txt
cp .env.example .env   # add your Gemini API key / Discord webhook
python3 main.py -t <target>
```

## Disclaimer

Built for authorized penetration testing and CTF/lab environments (HackTheBox, TryHackMe,
personal lab infrastructure) only. Do not run against systems you do not have explicit
permission to test.

## Author

Ryan Dube — [ryxvoid.xyz](https://ryxvoid.xyz) · [linkedin.com/in/ryxvoid](https://linkedin.com/in/ryxvoid)
