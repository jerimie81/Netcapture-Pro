"""Main menu with rich UI."""

from rich.panel   import Panel
from rich.table   import Table
from rich.text    import Text
from rich.prompt  import Prompt
from rich         import box
from rich.columns import Columns
from rich.align   import Align


MENU_ITEMS = [
    ("1", "capture",  "📡  CAPTURE",  "Discover & capture live traffic from a remote IP",   "cyan"),
    ("2", "analyze",  "🔍  ANALYZE",  "Parse a saved .pcap and reconstruct messages",       "green"),
    ("3", "decrypt",  "🔓  DECRYPT",  "Decrypt SSL/TLS & attempt traffic decryption",       "yellow"),
    ("4", "report",   "📄  REPORT",   "Generate a human-readable HTML/TXT report",          "magenta"),
    ("5", "quit",     "⏻   QUIT",     "Exit NetCapture Pro",                                "red"),
]


class MainMenu:
    def __init__(self, console):
        self.console = console

    def show(self) -> str:
        self.console.print()
        table = Table(box=box.ROUNDED, border_style="cyan", show_header=False,
                      padding=(0, 2), expand=False)
        table.add_column("Key",    style="bold cyan",    width=4)
        table.add_column("Module", style="bold white",   width=16)
        table.add_column("Description", style="dim white", width=48)

        for key, _, label, desc, color in MENU_ITEMS:
            table.add_row(
                f"[{color}]{key}[/{color}]",
                f"[{color}]{label}[/{color}]",
                desc
            )

        self.console.print(Align.center(table))
        self.console.print()

        choice = Prompt.ask(
            "[cyan]  ▶ Select module[/cyan]",
            choices=["1","2","3","4","5"],
            default="1"
        )
        mapping = {item[0]: item[1] for item in MENU_ITEMS}
        return mapping[choice]
