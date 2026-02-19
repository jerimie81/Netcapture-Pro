"""Analyze Flow - load pcap and reconstruct messages."""

import os, glob
from rich.prompt  import Prompt
from rich.panel   import Panel
from rich.table   import Table
from rich.padding import Padding
from rich         import box
from rich.text    import Text


class AnalyzeFlow:
    def __init__(self, console):
        self.console = console

    def _pick_pcap(self):
        c = self.console
        # Scan common output dirs for pcap files
        default_dir = os.path.expanduser("~/netcapture_output")
        pcaps = sorted(glob.glob(f"{default_dir}/**/*.pcap", recursive=True), reverse=True)

        if pcaps:
            c.print("\n[bold cyan]  Recent captures:[/bold cyan]\n")
            tbl = Table(box=box.MINIMAL, show_header=False, padding=(0,2))
            tbl.add_column("#", width=4, style="cyan")
            tbl.add_column("File", style="white")
            tbl.add_column("Size", style="dim", width=12)
            for i, p in enumerate(pcaps[:10], 1):
                size = os.path.getsize(p)
                sz   = f"{size//1024} KB" if size >= 1024 else f"{size} B"
                tbl.add_row(str(i), p, sz)
            c.print(tbl)
            c.print()
            sel = Prompt.ask("[cyan]  Select # or enter path[/cyan]").strip()
            if sel.isdigit() and 1 <= int(sel) <= len(pcaps):
                return pcaps[int(sel)-1]
            return sel
        else:
            return Prompt.ask("[cyan]  Enter .pcap file path[/cyan]").strip()

    def run(self):
        c = self.console
        c.clear()
        c.print(Panel(
            "[bold green]🔍  ANALYZE MODULE[/bold green]\n"
            "[dim]Parse a saved .pcap and reconstruct human-readable messages[/dim]",
            border_style="green", padding=(1, 4)
        ))

        pcap_path = self._pick_pcap()
        if not pcap_path or not os.path.exists(pcap_path):
            c.print(f"[red]  File not found: {pcap_path}[/red]")
            input("  Press Enter...")
            return

        c.print(f"\n  [green]✓[/green] Loading: [cyan]{pcap_path}[/cyan]")

        # Check for meta file
        meta_path = pcap_path.replace(".pcap","_meta.json")
        meta = {}
        if os.path.exists(meta_path):
            import json
            with open(meta_path) as f:
                meta = json.load(f)
            c.print(f"  [green]✓[/green] Metadata loaded")

        # Reconstruct
        with c.status("[green]  Reconstructing messages...[/green]", spinner="dots12"):
            from core.reconstructor import reconstruct
            messages = reconstruct(pcap_path)

        # Show summary
        c.print(f"\n  [bold green]Reconstruction complete:[/bold green]\n")
        tbl = Table(box=box.ROUNDED, border_style="green", header_style="bold green")
        tbl.add_column("Platform",  style="bold white",  min_width=28)
        tbl.add_column("Messages",  style="green",       width=12)
        tbl.add_column("Preview",   style="dim",         min_width=40)

        for platform, msgs in sorted(messages.items(), key=lambda x: -len(x[1])):
            if not msgs:
                continue
            first  = msgs[0]
            preview = (first.get("content") or first.get("query") or first.get("event") or "")[:60]
            tbl.add_row(platform, str(len(msgs)), preview)

        c.print(tbl)

        # Report generation
        c.print()
        out_dir = os.path.dirname(pcap_path)
        base    = os.path.splitext(os.path.basename(pcap_path))[0]

        from rich.prompt import Confirm
        if Confirm.ask("  [cyan]Generate HTML report?[/cyan]", default=True):
            from core.reporter import generate_html
            html_path = os.path.join(out_dir, f"{base}_report.html")
            generate_html(html_path, meta or {"target_ip": "unknown", "total_packets": 0}, messages)
            c.print(f"  [green]✓[/green] HTML Report → [cyan]{html_path}[/cyan]")

        if Confirm.ask("  [cyan]Generate text report?[/cyan]", default=True):
            from core.reporter import generate_txt
            txt_path = os.path.join(out_dir, f"{base}_report.txt")
            generate_txt(txt_path, meta or {"target_ip": "unknown", "total_packets": 0}, messages)
            c.print(f"  [green]✓[/green] Text Report → [cyan]{txt_path}[/cyan]")

        # Save raw messages JSON
        import json
        msg_path = os.path.join(out_dir, f"{base}_messages.json")
        serializable = {
            k: [{kk: list(vv) if isinstance(vv, set) else vv for kk, vv in m.items()} for m in v]
            for k, v in messages.items()
        }
        with open(msg_path, "w") as f:
            json.dump(serializable, f, indent=2)
        c.print(f"  [green]✓[/green] Raw JSON   → [cyan]{msg_path}[/cyan]")

        c.print("\n  [dim]Press Enter to return to menu...[/dim]")
        input()
