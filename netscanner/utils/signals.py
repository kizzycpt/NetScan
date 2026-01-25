import signal

STOP_REQUESTED = False

def install_sigint_handler(console):
    def _handle_sigint(signum, frame):
        global STOP_REQUESTED
        if STOP_REQUESTED:
            raise KeyboardInterrupt
        STOP_REQUESTED = True
        console.print("[yellow]Ctrl+C detected; finishing this run then exiting. Press Ctrl+C again to force quit.[/yellow]")

    signal.signal(signal.SIGINT, _handle_sigint)
