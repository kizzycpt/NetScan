import pyfiglet
from rich.console import Console

def print_banner(console: Console):
    title_text = pyfiglet.figlet_format("-----------\n SKO NET SCAN\n----------", font="slant", width=200)
    console.print(f"[cyan]{title_text}")

def print_menu(console: Console):
    console.print("[bold green]1. IDS Mode (baseline + alerts, then exit)")
    console.print("[bold green]2. Scan Mode (one-time snapshot)")
    console.print("[bold green]3. Exit")
