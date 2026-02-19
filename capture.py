"""Capture Flow UI - rich TUI for live traffic capture."""

import os, time
from datetime import datetime
from rich.prompt   import Prompt, Confirm
from rich.table    import Table
from rich.panel    import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.text     import Text
from rich.columns  import Columns
from rich          import box
from rich.live     import Live
from rich.layout   import Layout
from rich.align    import Align
from scapy.all     import get_if_list


class CaptureFlow:
    def __init__(self, console):
        self.console = console

    def _section(self, title, icon=""):
        self.console.print(f"\n[bold cyan]  ── {icon} {title} ──[/bold cyan]\n")

    def run(self):
        c = self.console
        c.clear()
        c.print(Panel(
            "[bold cyan]📡  LIVE CAPTURE MODULE[/bold cyan]\n"
            "[dim]Discover and capture network traffic from a target IP[/dim]",
            border_style="cyan", padding=(1, 4)
        ))

        # ── Target IP ────────────────────────────────────
        self._section("Target Configuration", "🎯")
        target = Prompt.ask("[cyan]  Target IP address[/cyan]").strip()
        if not target:
            c.print("[red]  No IP entered.[/red]")
            return

        # ── Interface ─────────────────────────────────────
        ifaces = [i for i in get_if_list() if i != "lo"]
        c.print(f"[dim]  Interfaces: {', '.join(ifaces)}[/dim]")
        iface = Prompt.ask("[cyan]  Network interface[/cyan]", default=ifaces[0] if ifaces else "eth0")

        # ── Durations ─────────────────────────────────────
        disc_dur = int(Prompt.ask("[cyan]  Discovery duration (seconds)[/cyan]", default="20"))

        # ── Engine ───────────────────────────────────────
        from core.engine import CaptureEngine
        engine = CaptureEngine(target, iface)

        # ARP scan
        self._section("Device Discovery", "📍")
        with c.status("[cyan]  ARP scanning...[/cyan]", spinner="dots"):
            mac = engine.arp_scan()
            if mac:
                from core.engine import mac_vendor
                vendor = mac_vendor(mac)
                c.print(f"  [green]✓[/green] MAC: [cyan]{mac}[/cyan]  Vendor: [yellow]{vendor}[/yellow]")
                engine.devices[target] = {
                    "ip": target, "mac": mac, "vendor": vendor,
                    "os_guess": "Unknown", "ttl": None,
                    "hostnames": set(), "open_ports": set()
                }
            else:
                c.print("  [yellow]⚠  ARP scan got no response (target may be remote/routed)[/yellow]")

        # ── Discovery sniff ───────────────────────────────
        self._section("Traffic Discovery", "🔍")
        c.print(f"  [dim]Listening on [cyan]{iface}[/cyan] for [yellow]{disc_dur}s[/yellow]...[/dim]\n")

        # Live stats table
        stats_data = {"elapsed": 0, "packets": 0, "bytes": 0, "cats": 0}

        def progress_cb(elapsed, total, pkts, byts):
            stats_data.update(elapsed=elapsed, packets=pkts, bytes=byts,
                              cats=len(engine.active_traffic()))

        from threading import Thread
        sniff_done = [False]
        def _run_sniff():
            engine.sniff(disc_dur, progress_cb)
            sniff_done[0] = True

        t = Thread(target=_run_sniff, daemon=True)
        t.start()

        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[cyan]{task.description}[/cyan]"),
            BarColumn(bar_width=30, style="cyan", complete_style="bright_cyan"),
            TextColumn("[white]{task.fields[pkts]} pkts[/white]"),
            TextColumn("[yellow]{task.fields[cats]} categories[/yellow]"),
            TimeElapsedColumn(),
            console=c, transient=True
        ) as prog:
            task = prog.add_task("Scanning...", total=disc_dur, pkts=0, cats=0)
            while not sniff_done[0]:
                prog.update(task, completed=stats_data["elapsed"],
                            pkts=stats_data["packets"], cats=stats_data["cats"])
                time.sleep(0.3)
            prog.update(task, completed=disc_dur)

        t.join(timeout=2)

        # ── Show discovered traffic ───────────────────────
        active = engine.active_traffic()
        if not active:
            c.print("[red]  No traffic captured. Is the target active?[/red]")
            return

        self._section("Discovered Traffic", "📊")
        tbl = Table(box=box.ROUNDED, border_style="cyan", show_header=True,
                    header_style="bold cyan", padding=(0, 2))
        tbl.add_column("#",        width=4)
        tbl.add_column("Category", width=24)
        tbl.add_column("Packets",  width=10)
        tbl.add_column("Bytes",    width=12)
        tbl.add_column("Top Domains", min_width=30)

        indexed = {}
        for i, (cat, info) in enumerate(sorted(active.items(), key=lambda x: -x[1]["count"]), 1):
            indexed[i] = cat
            doms = ", ".join(list(info["domains"])[:3])
            b = info["bytes"]
            bs = f"{b:,} B" if b < 1024 else (f"{b//1024:,} KB" if b < 1024**2 else f"{b//1024//1024:.1f} MB")
            tbl.add_row(str(i), f"[bold]{cat}[/bold]", f"[green]{info['count']:,}[/green]",
                        f"[yellow]{bs}[/yellow]", f"[dim]{doms}[/dim]")

        c.print(tbl)

        # Show device info
        self._section("Device Profile", "🖥")
        for ip, dev in engine.devices.items():
            dtbl = Table(box=box.MINIMAL, show_header=False, padding=(0,2))
            dtbl.add_column("k", style="dim", width=16)
            dtbl.add_column("v", style="white")
            dtbl.add_row("IP",          f"[cyan]{ip}[/cyan]")
            dtbl.add_row("MAC",         dev.get("mac") or "—")
            dtbl.add_row("Vendor",      dev.get("vendor") or "Unknown")
            dtbl.add_row("OS Guess",    f"[yellow]{dev.get('os_guess','Unknown')}[/yellow]")
            dtbl.add_row("Open Ports",  ", ".join(str(p) for p in sorted(dev.get("open_ports",[]))[:12]) or "—")
            dtbl.add_row("Hostnames",   ", ".join(list(dev.get("hostnames",[]))[:5]) or "—")
            c.print(dtbl)

        # ── Select categories ─────────────────────────────
        self._section("Category Selection", "✅")
        c.print("  Enter numbers (comma-separated) or [bold]all[/bold]:")
        sel_raw = Prompt.ask("[cyan]  Selection[/cyan]", default="all").strip().lower()

        if sel_raw == "all":
            selected = list(indexed.values())
        else:
            selected = [indexed[int(x.strip())] for x in sel_raw.split(",")
                        if x.strip().isdigit() and int(x.strip()) in indexed]

        if not selected:
            c.print("[red]  No valid selection.[/red]")
            return

        c.print(f"  [green]✓[/green] Selected: {', '.join(selected)}")

        # ── Output directory ──────────────────────────────
        cap_dur = int(Prompt.ask("[cyan]  Targeted capture duration (seconds)[/cyan]", default="60"))
        default_dir = os.path.expanduser(f"~/netcapture_output/{target.replace('.','_')}")
        out_dir = Prompt.ask("[cyan]  Output directory[/cyan]", default=default_dir)

        # ── Targeted capture ──────────────────────────────
        self._section("Capturing", "🔴")
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_out = os.path.join(out_dir, f"capture_{ts}.pcap")
        meta_out = os.path.join(out_dir, f"capture_{ts}_meta.json")

        # Reset & sniff again with targeted filter
        engine2 = CaptureEngine(target, iface)
        engine2.devices = engine.devices
        cap_stats = {"elapsed": 0, "packets": 0}
        done2 = [False]
        def _run2():
            engine2.sniff(cap_dur, lambda e,t,p,b: cap_stats.update(elapsed=e, packets=p))
            done2[0] = True
        t2 = Thread(target=_run2, daemon=True)
        t2.start()

        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[bold red]CAPTURING[/bold red]"),
            BarColumn(bar_width=30, style="red", complete_style="bright_red"),
            TextColumn("[white]{task.fields[pkts]} pkts[/white]"),
            TimeElapsedColumn(),
            console=c, transient=True
        ) as prog:
            task = prog.add_task("Capturing...", total=cap_dur, pkts=0)
            while not done2[0]:
                prog.update(task, completed=cap_stats["elapsed"], pkts=cap_stats["packets"])
                time.sleep(0.3)
            prog.update(task, completed=cap_dur)

        t2.join(timeout=2)

        # Save
        n = engine2.save_pcap(pcap_out, selected)
        meta = engine2.save_meta(meta_out, {"categories_captured": selected})
        # merge device info
        import json
        with open(meta_out) as f:
            mdata = json.load(f)
        mdata["devices"] = {
            ip: {k: list(v) if isinstance(v, set) else v for k,v in dev.items()}
            for ip, dev in engine.devices.items()
        }
        with open(meta_out, "w") as f:
            json.dump(mdata, f, indent=2)

        c.print(f"\n  [green]✓[/green] Saved [bold]{n}[/bold] packets → [cyan]{pcap_out}[/cyan]")
        c.print(f"  [green]✓[/green] Metadata → [cyan]{meta_out}[/cyan]")

        # Offer quick report
        if Confirm.ask("\n  [cyan]Generate report now?[/cyan]", default=True):
            from core.reconstructor import reconstruct
            from core.reporter      import generate_html, generate_txt
            msgs = reconstruct(pcap_out)
            html_out = os.path.join(out_dir, f"report_{ts}.html")
            txt_out  = os.path.join(out_dir, f"report_{ts}.txt")
            generate_html(html_out, mdata, msgs)
            generate_txt(txt_out, mdata, msgs)
            c.print(f"  [green]✓[/green] HTML report → [cyan]{html_out}[/cyan]")
            c.print(f"  [green]✓[/green] Text report → [cyan]{txt_out}[/cyan]")

        c.print("\n  [dim]Press Enter to return to menu...[/dim]")
        input()
