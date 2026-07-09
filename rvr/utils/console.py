"""
RVR — Console utilities v3
Hacker aesthetic banner with block font
"""

from rich.console import Console
from rich.text import Text
from rich.rule import Rule
from contextlib import contextmanager
from datetime import datetime

console = Console()

BANNER = """\
\033[38;5;69m
                                ██████╗ ██╗   ██╗██████╗ 
                                ██╔══██╗██║   ██║██╔══██╗
                                ██████╔╝██║   ██║██████╔╝
                                ██╔══██╗╚██╗ ██╔╝██╔══██╗
                                ██║  ██║ ╚████╔╝ ██║  ██║
                                ╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝\033[0m"""

TAGLINE = "  \033[38;5;60m[ RYXVOID RECON FRAMEWORK ]  ·  v1.0.0  ·  by ryx13  ·  automated pentesting intelligence\033[0m"

DIVIDER = "\033[38;5;237m" + "─" * 60 + "\033[0m"


def print_banner():
    print(BANNER)
    print(TAGLINE)
    print()


def log_info(msg: str):
    console.print(f"  [cyan]→[/cyan] {msg}")


def log_success(msg: str):
    console.print(f"  [green]✓[/green] {msg}")


def log_warn(msg: str):
    console.print(f"  [yellow]⚠[/yellow] {msg}")


def log_error(msg: str):
    console.print(f"  [red]✗[/red] {msg}")


def log_section(title: str):
    console.print()
    console.rule(f"[bold cyan]{title}[/bold cyan]", style="dim blue")
    console.print()
