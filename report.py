"""Report Flow UI - generate reports from captured data."""

import os, glob, json
from rich.prompt  import Prompt, Confirm
from rich.panel   import Panel
from rich.table   import Table
from rich         import box


class ReportFlow:
    def __init__(self, console):
        self.console = console

    def _pick_file(self, ext, label):
        default_dir = os.path.expanduser("~/netcapture_output")
        files = sorted(glob.glob(f"{default_dir}/**/*{ext}", recursive=True), reverse=True)[:10]
        c = self.console
        if files:
            c.print(f"\n  [bold cyan]Recent {label} files:[/bold cyan]")
            for i, f in enumerate(files, 1):
                c.print(f"    [{i}] {f}")
            c.print()
            sel = Prompt.ask(f"[cyan]  Select # or enter path[/cyan]").strip()
            if sel.isdigit() and 1 <= int(sel) <= len(files):
                return files[int(sel)-1]
            return sel
        return Prompt.ask(f"[cyan]  Enter {label} file path[/cyan]").strip()

    def run(self):
        c = self.console
        c.clear()
        c.print(Panel(
            "[bold magenta]📄  REPORT MODULE[/bold magenta]\n"
            "[dim]Generate human-readable HTML and TXT reports from any capture[/dim]",
            border_style="magenta", padding=(1, 4)
        ))

        # Pick pcap
        pcap = self._pick_file(".pcap", ".pcap")
        if not pcap or not os.path.exists(pcap):
            c.print(f"[red]  File not found: {pcap}[/red]")
            input("  Press Enter..."); return

        # Pick meta
        meta = {}
        meta_path = pcap.replace(".pcap", "_meta.json")
        if os.path.exists(meta_path):
            with open(meta_path) as f:
                meta = json.load(f)
            c.print(f"  [green]✓[/green] Loaded metadata from [cyan]{meta_path}[/cyan]")
        else:
            c.print("  [yellow]⚠  No metadata file found. Report will have limited info.[/yellow]")

        # Reconstruct messages
        with c.status("[magenta]  Reconstructing messages from pcap...[/magenta]", spinner="aesthetic"):
            from core.reconstructor import reconstruct
            messages = reconstruct(pcap)

        total_msgs = sum(len(v) for v in messages.values())
        c.print(f"  [green]✓[/green] Found [bold]{total_msgs}[/bold] items across [bold]{len(messages)}[/bold] platforms\n")

        out_dir  = os.path.dirname(pcap)
        base     = os.path.splitext(os.path.basename(pcap))[0]

        if not meta:
            meta = {"target_ip": "unknown", "total_packets": 0, "devices": {}, "traffic_summary": {}}

        # Generate HTML
        html_path = os.path.join(out_dir, f"{base}_report.html")
        from core.reporter import generate_html, generate_txt
        generate_html(html_path, meta, messages)
        c.print(f"  [green]✓[/green] HTML report → [cyan]{html_path}[/cyan]")

        # Generate TXT
        txt_path = os.path.join(out_dir, f"{base}_report.txt")
        generate_txt(txt_path, meta, messages)
        c.print(f"  [green]✓[/green] Text report → [cyan]{txt_path}[/cyan]")

        # Save messages JSON
        msg_path = os.path.join(out_dir, f"{base}_messages.json")
        serializable = {
            k: [{kk: list(vv) if isinstance(vv, set) else vv for kk, vv in m.items()} for m in v]
            for k, v in messages.items()
        }
        with open(msg_path, "w") as f:
            json.dump(serializable, f, indent=2, default=str)
        c.print(f"  [green]✓[/green] Messages JSON → [cyan]{msg_path}[/cyan]")

        # Summary table
        c.print()
        tbl = Table(box=box.ROUNDED, border_style="magenta", header_style="bold magenta")
        tbl.add_column("Platform",  style="white",   min_width=28)
        tbl.add_column("Items",     style="magenta", width=10)
        tbl.add_column("Preview",   style="dim",     min_width=40)
        for platform, msgs in sorted(messages.items(), key=lambda x: -len(x[1])):
            if not msgs: continue
            first   = msgs[0]
            preview = (first.get("content") or first.get("query") or
                       first.get("event") or str(first))[:60]
            tbl.add_row(platform, str(len(msgs)), preview)
        c.print(tbl)

        c.print(f"\n  [bold green]Open the HTML report in a browser for the full visual report.[/bold green]")
        c.print(f"  [dim]xdg-open {html_path}[/dim]")

        c.print("\n  [dim]Press Enter to return to menu...[/dim]")
        input()
