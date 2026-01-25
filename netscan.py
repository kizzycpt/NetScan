import sys
from rich.console import Console

from netscanner.ui.banner import print_banner, print_menu
from netscanner.utils.signals import install_sigint_handler
from netscanner.modes.scan_mode import run_scan_mode
from netscanner.modes.ids_mode import run_ids_once, run_ids_loop

def main():
    console = Console()
    install_sigint_handler(console)

    # CLI flags
    if "--ids-once" in sys.argv:
        run_ids_once(console)
        return

    if "--ids-every" in sys.argv:
        try:
            i = sys.argv.index("--ids-every")
            hours = float(sys.argv[i + 1]) if i + 1 < len(sys.argv) else 6.0
        except Exception:
            hours = 6.0
        run_ids_loop(console, hours)
        return

    # Interactive menu
    print_banner(console)
    print_menu(console)

    choice = console.input("[bold green]Select an option: ").strip()

    if choice == "1":
        run_ids_loop(console, 6.0)
    elif choice == "2":
        run_scan_mode(console)
    elif choice == "3":
        print("Exiting...")
    else:
        print("[!] Invalid choice.")

if __name__ == "__main__":
    main()
