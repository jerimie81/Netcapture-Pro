"""Decrypt Flow UI - TLS key log, WPA2, payload decoder."""

import os, glob
from rich.prompt  import Prompt, Confirm
from rich.panel   import Panel
from rich.table   import Table
from rich.text    import Text
from rich         import box


DECRYPT_METHODS = [
    ("1", "tls_keylog",  "🔐 TLS via SSLKEYLOGFILE", "Decrypt HTTPS using browser/app key log file"),
    ("2", "wpa2",        "📶 WPA2-PSK Wi-Fi",          "Decrypt Wi-Fi traffic with passphrase + SSID"),
    ("3", "payload",     "🔠 Payload Decoder",          "Decode Base64 / URL / Hex / JSON payloads"),
    ("4", "certs",       "📜 TLS Certificate Extract",  "Extract & display TLS certificates from pcap"),
    ("5", "rtsp",        "📹 RTSP Stream URLs",          "Extract media stream URLs from capture"),
    ("6", "back",        "↩  Back",                     "Return to main menu"),
]


class DecryptFlow:
    def __init__(self, console):
        self.console = console

    def _pick_pcap(self, prompt="  .pcap file path"):
        default_dir = os.path.expanduser("~/netcapture_output")
        pcaps = sorted(glob.glob(f"{default_dir}/**/*.pcap", recursive=True), reverse=True)[:8]
        if pcaps:
            self.console.print("\n[bold yellow]  Recent captures:[/bold yellow]")
            for i, p in enumerate(pcaps, 1):
                self.console.print(f"    [{i}] {p}")
            self.console.print()
            sel = Prompt.ask(f"[yellow]{prompt} (# or path)[/yellow]").strip()
            if sel.isdigit() and 1 <= int(sel) <= len(pcaps):
                return pcaps[int(sel)-1]
            return sel
        return Prompt.ask(f"[yellow]{prompt}[/yellow]").strip()

    def run(self):
        c = self.console
        while True:
            c.clear()
            c.print(Panel(
                "[bold yellow]🔓  DECRYPT MODULE[/bold yellow]\n"
                "[dim]TLS decryption, Wi-Fi decryption, payload decoding[/dim]",
                border_style="yellow", padding=(1, 4)
            ))

            tbl = Table(box=box.ROUNDED, border_style="yellow", show_header=False, padding=(0,3))
            tbl.add_column("Key",    style="bold yellow", width=4)
            tbl.add_column("Method", style="bold white",  width=28)
            tbl.add_column("Desc",   style="dim",         width=50)
            for key, _, label, desc in DECRYPT_METHODS:
                tbl.add_row(key, label, desc)
            c.print(tbl)
            c.print()

            choice = Prompt.ask("[yellow]  Select method[/yellow]",
                                choices=["1","2","3","4","5","6"], default="1")

            if choice == "6":
                return

            elif choice == "1":   # TLS keylog
                pcap = self._pick_pcap()
                if not os.path.exists(pcap):
                    c.print(f"[red]  File not found: {pcap}[/red]"); input("  Enter..."); continue
                c.print("\n[dim]  The SSLKEYLOGFILE is set in your browser/app environment.[/dim]")
                c.print("[dim]  Chrome/Firefox: set env var SSLKEYLOGFILE=~/ssl_keys.log before launch.[/dim]\n")
                keylog = Prompt.ask("[yellow]  Path to SSLKEYLOGFILE[/yellow]",
                                    default=os.path.expanduser("~/ssl_keys.log"))
                out_dir = os.path.dirname(pcap)
                with c.status("[yellow]  Decrypting TLS...[/yellow]", spinner="dots"):
                    from core.decryptor import decrypt_tls_with_keylog
                    result = decrypt_tls_with_keylog(pcap, keylog, out_dir)
                if result["success"]:
                    c.print(f"\n  [green]✓[/green] {result['message']}")
                    if result["records"]:
                        c.print(f"\n  [bold]Sample decrypted records:[/bold]")
                        for line in result["records"][:15]:
                            c.print(f"  [dim]{line[:120]}[/dim]")
                else:
                    c.print(f"\n  [red]✗[/red] {result['message']}")

            elif choice == "2":   # WPA2
                pcap = self._pick_pcap()
                if not os.path.exists(pcap):
                    c.print(f"[red]  File not found: {pcap}[/red]"); input("  Enter..."); continue
                ssid = Prompt.ask("[yellow]  Wi-Fi SSID[/yellow]")
                psk  = Prompt.ask("[yellow]  Wi-Fi Passphrase[/yellow]", password=True)
                out_dir = os.path.dirname(pcap)
                with c.status("[yellow]  Decrypting WPA2...[/yellow]", spinner="dots"):
                    from core.decryptor import decrypt_wifi_wpa2
                    result = decrypt_wifi_wpa2(pcap, psk, ssid, out_dir)
                if result.get("success"):
                    c.print(f"\n  [green]✓[/green] Output: [cyan]{result['output']}[/cyan]")
                    if result.get("records"):
                        for line in result["records"][:15]:
                            c.print(f"  [dim]{line}[/dim]")
                else:
                    c.print(f"\n  [red]✗[/red] {result.get('message','Failed')}")

            elif choice == "3":   # Payload decoder
                c.print("\n  [bold yellow]Payload Decoder[/bold yellow]")
                c.print("  [dim]Paste raw payload (Base64, URL-encoded, hex, JSON).[/dim]")
                c.print("  [dim]Enter blank line to finish.[/dim]\n")
                lines = []
                while True:
                    line = input("  > ")
                    if not line:
                        break
                    lines.append(line)
                raw = "\n".join(lines)
                if raw:
                    from core.decryptor import decode_payload
                    results = decode_payload(raw)
                    c.print()
                    for method, decoded in results.items():
                        c.print(Panel(decoded[:1000], title=f"[yellow]{method}[/yellow]",
                                      border_style="yellow", padding=(1,2)))

            elif choice == "4":   # TLS certs
                pcap = self._pick_pcap()
                if not os.path.exists(pcap):
                    c.print(f"[red]  File not found: {pcap}[/red]"); input("  Enter..."); continue
                with c.status("[yellow]  Extracting certificates...[/yellow]", spinner="dots"):
                    from core.decryptor import extract_certificates
                    certs = extract_certificates(pcap, os.path.dirname(pcap))
                if certs:
                    tbl2 = Table(box=box.ROUNDED, border_style="yellow", header_style="bold yellow")
                    tbl2.add_column("Time",   style="dim",    width=22)
                    tbl2.add_column("Src",    style="cyan",   width=18)
                    tbl2.add_column("Dst",    style="cyan",   width=18)
                    tbl2.add_column("CN",     style="white",  min_width=20)
                    tbl2.add_column("SAN",    style="dim",    min_width=20)
                    for cert in certs[:30]:
                        tbl2.add_row(cert["time"][:20], cert["src"], cert["dst"],
                                     cert["cn"][:30], cert["san"][:30])
                    c.print(tbl2)
                    c.print(f"  [green]{len(certs)} certificates found.[/green]")
                else:
                    c.print("  [yellow]No TLS certificates found (may need tshark installed).[/yellow]")

            elif choice == "5":   # RTSP
                pcap = self._pick_pcap()
                if not os.path.exists(pcap):
                    c.print(f"[red]  File not found: {pcap}[/red]"); input("  Enter..."); continue
                with c.status("[yellow]  Extracting RTSP streams...[/yellow]", spinner="dots"):
                    from core.decryptor import extract_rtsp
                    streams = extract_rtsp(pcap)
                if streams:
                    for s in streams:
                        c.print(f"  [cyan]{s['method']}[/cyan]  [white]{s['url']}[/white]  [dim]{s['time'][:20]}[/dim]")
                else:
                    c.print("  [yellow]No RTSP streams found.[/yellow]")

            c.print("\n  [dim]Press Enter to continue...[/dim]")
            input()
