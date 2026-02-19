#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════╗
║           NetCapture Pro - Main Launcher              ║
║   Authorized Network Traffic Analysis Suite           ║
╚═══════════════════════════════════════════════════════╝
"""

import os, sys, subprocess, importlib

# ── Root check ──────────────────────────────────────────
if os.geteuid() != 0:
    print("\033[91m[!] NetCapture Pro requires root. Run: sudo python3 netcapture.py\033[0m")
    sys.exit(1)

# ── Auto-install dependencies ────────────────────────────
DEPS = {
    "scapy":   "scapy",
    "rich":    "rich",
    "manuf":   "manuf",
    "cryptography": "cryptography",
    "dpkt":    "dpkt",
}

def install_deps():
    missing = []
    for mod, pkg in DEPS.items():
        try:
            importlib.import_module(mod)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"\033[93m[*] Installing: {', '.join(missing)}...\033[0m")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--break-system-packages", "-q"] + missing,
            check=True
        )

install_deps()

# ── Now import rich & launch ─────────────────────────────
from rich.console import Console
from rich.panel   import Panel
from rich.text    import Text
from rich.align   import Align
from rich import print as rprint
import time

console = Console()

def splash():
    console.clear()
    art = Text()
    art.append("\n")
    art.append("  ███╗   ██╗███████╗████████╗ ██████╗ █████╗ ██████╗\n",  style="bold cyan")
    art.append("  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗██╔══██╗\n", style="bold cyan")
    art.append("  ██╔██╗ ██║█████╗     ██║   ██║     ███████║██████╔╝\n",  style="bold bright_cyan")
    art.append("  ██║╚██╗██║██╔══╝     ██║   ██║     ██╔══██║██╔═══╝\n",  style="bold bright_cyan")
    art.append("  ██║ ╚████║███████╗   ██║   ╚██████╗██║  ██║██║\n",      style="bold white")
    art.append("  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  PRO\n", style="bold white")
    art.append("\n")
    art.append("         Authorized Network Traffic Analysis Suite\n", style="dim white")
    art.append("         ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", style="dim cyan")
    art.append("   ⚠  FOR AUTHORIZED TESTING ON OWNED/PERMITTED DEVICES ONLY  ⚠\n", style="bold yellow")

    console.print(Panel(art, border_style="cyan", padding=(0, 2)))
    time.sleep(1)

def main_menu():
    from ui.menu    import MainMenu
    from ui.capture import CaptureFlow
    from ui.analyze import AnalyzeFlow
    from ui.decrypt import DecryptFlow
    from ui.report  import ReportFlow

    splash()
    menu = MainMenu(console)

    while True:
        choice = menu.show()
        if choice == "capture":
            CaptureFlow(console).run()
        elif choice == "analyze":
            AnalyzeFlow(console).run()
        elif choice == "decrypt":
            DecryptFlow(console).run()
        elif choice == "report":
            ReportFlow(console).run()
        elif choice == "quit":
            console.print("\n[cyan]  Goodbye.[/cyan]\n")
            sys.exit(0)

if __name__ == "__main__":
    main_menu()
