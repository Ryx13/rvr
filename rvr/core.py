"""
RVR — Core orchestrator
Manages the full scan pipeline and micro-variant mode
"""

from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from rich.prompt import Prompt, IntPrompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn, TimeElapsedColumn

from rvr.utils.console import (
    console, log_info, log_warn, log_error, log_section,
    triggered_modules_table, end_summary_panel,
)
from rvr.utils.state import RVRState
from rvr.utils.config import get_config

# Profile settings — sourced from config.yaml (rvr/config/config.yaml or
# --config / RVR_CONFIG override), falling back to built-in defaults if the
# file is missing or a profile isn't defined there. Kept as a module-level
# name for backward compatibility with anything importing PROFILES directly.
PROFILES = get_config().profiles


class RVRCore:
    def __init__(self, state: RVRState):
        self.state = state
        self.config = get_config()
        profiles = self.config.profiles
        if state.profile not in profiles:
            log_warn(f"Profile '{state.profile}' not found in config — falling back to 'normal'")
        self.profile = profiles.get(state.profile, profiles.get("normal", PROFILES["normal"]))
        self.start_time = datetime.now()

    # ── Full suite mode ────────────────────────────────────────────
    def run_full(self):
        """Run all applicable modules based on target type and discoveries"""
        s = self.state

        # Phase 1 — OSINT (domain targets only)
        if "osint" not in s.skip and s.target_type == "domain":
            log_section("Phase 1 — Passive OSINT")
            self._run_module("osint", self._phase_osint)

        # Phase 2 — Active network sweep (always)
        if "network" not in s.skip:
            log_section("Phase 2 — Network Sweep")
            self._run_module("network", self._phase_network)

        # Phase 3 — Conditional modules based on open ports
        if s.open_ports:
            self._run_conditional_phases()

        # Phase 4 — AI analysis
        if "ai" not in s.skip:
            log_section("Phase 4 — AI Analysis")
            self._run_module("ai", self._phase_ai)

        # Phase 5 — Report generation
        if "report" not in s.skip:
            log_section("Phase 5 — Report Generation")
            self._run_module("report", self._phase_report, always=True)

        # Phase 6 — Discord notification
        if not s.no_discord:
            self._phase_discord()

        # Save final state
        s.save()
        elapsed = datetime.now() - self.start_time

        console.print()
        end_summary_panel(s, elapsed.seconds)

    def _run_conditional_phases(self):
        """Run phases conditionally based on open ports, driven by the module registry"""
        from rvr.modules.registry import get_triggered_modules, load_module_class

        s = self.state
        triggered = get_triggered_modules(s)

        if s.resume:
            already_done = [spec for spec in triggered if s.is_complete(spec.name)]
            if already_done:
                log_info(f"Resume: skipping already-completed module(s): {', '.join(spec.name for spec in already_done)}")
            triggered = [spec for spec in triggered if not s.is_complete(spec.name)]

        if not triggered:
            log_warn("No conditional modules triggered by open ports")
            return

        log_section("Phase 3 — Conditional Enumeration")
        triggered_modules_table(triggered)

        def run_spec(spec):
            cls = load_module_class(spec)
            cls(self.state, self.profile).run()

        # Run conditional modules in parallel, with a live progress bar
        # tracking overall completion. Individual modules still print their
        # own detailed step-by-step status as before — Rich supports plain
        # console.print() calls from other threads while a Progress bar is
        # active on the same console, so the two coexist without conflict.
        # progress.update() calls below only ever happen on the main thread
        # (as_completed() yields here, not in the worker threads), so there's
        # no concurrent-write risk on the progress bar itself either.
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]Conditional enumeration[/bold cyan]"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task("modules", total=len(triggered))

            with ThreadPoolExecutor(max_workers=self.state.threads) as executor:
                futures = {
                    executor.submit(run_spec, spec): spec.name
                    for spec in triggered
                }
                for future in as_completed(futures):
                    name = futures[future]
                    try:
                        future.result()
                        self.state.mark_complete(name)
                    except Exception as e:
                        log_error(f"Module '{name}' failed: {e}")
                        self.state.mark_failed(name)
                    progress.advance(task)

    def _run_module(self, name: str, func: Callable, always: bool = False):
        """Run a single module with error handling. If --resume is set and
        this module already succeeded in a prior run, skip it — unless
        always=True (used for report generation, which should reflect
        whatever the current state is even when resuming)."""
        if self.state.resume and not always and self.state.is_complete(name):
            log_info(f"Resume: skipping '{name}' — already completed")
            return
        try:
            func()
            self.state.mark_complete(name)
        except Exception as e:
            log_error(f"Module '{name}' failed: {e}")
            self.state.mark_failed(name)

    # ── Phase implementations ──────────────────────────────────────
    def _phase_osint(self):
        from rvr.modules.osint import OSINTModule
        OSINTModule(self.state, self.profile).run()

    def _phase_network(self):
        from rvr.modules.network import NetworkModule
        mod = NetworkModule(self.state, self.profile)
        mod.run()
        if self.state.udp_scan:
            mod.run_udp()

    def _phase_ai(self):
        from rvr.modules.ai_analysis import AIModule
        AIModule(self.state).run()

    def _phase_report(self):
        from rvr.output.pdf_report import PDFReport
        PDFReport(self.state).generate()

    def _phase_discord(self):
        from rvr.output.discord_notify import DiscordNotifier
        DiscordNotifier(self.state).send()

    # ── Micro-variant mode ─────────────────────────────────────────
    def run_micro(self, tool: str):
        """Run a single tool in interactive mode"""
        log_section(f"Micro-variant — {tool}")
        log_info(f"Running {tool} against {self.state.target}")

        micro_map = {
            "nmap":       self._micro_nmap,
            "ffuf":       self._micro_ffuf,
            "subfinder":  self._micro_subfinder,
            "nuclei":     self._micro_nuclei,
            "enum4linux": self._micro_enum4linux,
            "netexec":    self._micro_netexec,
            "snmpwalk":   self._micro_snmpwalk,
            "whatweb":    self._micro_whatweb,
            "ftp":        self._micro_ftp,
            "ldapsearch": self._micro_ldapsearch,
            "rdp":        self._micro_rdp,
        }

        fn = micro_map.get(tool)
        if fn:
            fn()
        else:
            log_error(f"Unknown tool: {tool}")

        self.state.save()

    def _micro_nmap(self):
        console.print("[cyan]Nmap options:[/cyan]")
        console.print("  [1] Quick scan (top 1000 ports)")
        console.print("  [2] Full port scan (1-65535)")
        console.print("  [3] UDP scan (top 200)")
        console.print("  [4] Custom flags")
        choice = IntPrompt.ask("Select", choices=["1", "2", "3", "4"], default=1)

        extra = ""
        if choice == 1:
            extra = "--top-ports 1000"
        elif choice == 2:
            extra = "-p-"
        elif choice == 3:
            extra = "-sU --top-ports 200"
        elif choice == 4:
            extra = Prompt.ask("Enter custom nmap flags").strip()

        from rvr.modules.network import NetworkModule
        mod = NetworkModule(self.state, self.profile)
        mod.run(extra_flags=extra)

    def _micro_ffuf(self):
        console.print("[cyan]ffuf options:[/cyan]")
        url = Prompt.ask("Target URL", default=f"http://{self.state.target}/FUZZ")
        default_wordlist = self.config.wordlist("web_common") or "/usr/share/seclists/Discovery/Web-Content/common.txt"
        wordlist = Prompt.ask("Wordlist", default=default_wordlist)
        extensions = Prompt.ask("Extensions (e.g. php,html,txt)", default="").strip()

        from rvr.modules.web import WebModule
        mod = WebModule(self.state, self.profile)
        mod.run_ffuf(url=url, wordlist=wordlist, extensions=extensions)

    def _micro_subfinder(self):
        from rvr.modules.osint import OSINTModule
        OSINTModule(self.state, self.profile).run_subfinder()

    def _micro_nuclei(self):
        console.print("[cyan]Nuclei options:[/cyan]")
        console.print("  [1] Default templates")
        console.print("  [2] CVE templates only")
        console.print("  [3] Severity: critical + high only")
        choice = IntPrompt.ask("Select", choices=["1", "2", "3"], default=1)

        from rvr.modules.web import WebModule
        mod = WebModule(self.state, self.profile)
        mod.run_nuclei(choice=str(choice))

    def _micro_enum4linux(self):
        from rvr.modules.smb import SMBModule
        SMBModule(self.state, self.profile).run()

    def _micro_netexec(self):
        console.print("[cyan]NetExec options:[/cyan]")
        console.print("  [1] SMB — anonymous login check")
        console.print("  [2] SMB — share enumeration")
        console.print("  [3] RID cycling")
        choice = IntPrompt.ask("Select", choices=["1", "2", "3"], default=1)

        from rvr.modules.smb import SMBModule
        SMBModule(self.state, self.profile).run_netexec(choice=str(choice))

    def _micro_snmpwalk(self):
        from rvr.modules.snmp import SNMPModule
        SNMPModule(self.state, self.profile).run()

    def _micro_whatweb(self):
        from rvr.modules.web import WebModule
        WebModule(self.state, self.profile).run_whatweb()

    def _micro_ftp(self):
        from rvr.modules.ftp import FTPModule
        FTPModule(self.state, self.profile).run()

    def _micro_ldapsearch(self):
        from rvr.modules.ldap_enum import LDAPModule
        LDAPModule(self.state, self.profile).run()

    def _micro_rdp(self):
        from rvr.modules.rdp import RDPModule
        RDPModule(self.state, self.profile).run()