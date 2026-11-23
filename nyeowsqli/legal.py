"""Startup banner and legal disclaimer (Computer Crimes Act 1997, Malaysia)."""

import sys

from rich.console import Console
from rich.panel import Panel

from . import TOOL_NAME, __version__

BANNER = r"""
 _   ___   _____ _____        __  ____   ___  _     _
| \ | \ \ / / ____/ _ \ \      / / / ___| / _ \| |   (_)
|  \| |\ V /|  _|| | | \ \ /\ / /  \___ \| | | | |   | |
| |\  | | | | |__| |_| |\ V  V /    ___) | |_| | |___| |
|_| \_| |_| |_____\___/  \_/\_/    |____/ \__\_\_____|_|
"""

DISCLAIMER = """[bold]LEGAL DISCLAIMER - READ BEFORE CONTINUING[/bold]

This tool sends SQL injection test payloads to web applications.

Under Malaysia's [bold]Computer Crimes Act 1997[/bold]:
  - Section 3: unauthorised access to computer material is an offence
    (fine up to RM50,000 and/or up to 5 years' imprisonment).
  - Section 4: unauthorised access with intent to commit a further offence
    (fine up to RM150,000 and/or up to 10 years' imprisonment).
  - Section 5: unauthorised modification of computer contents is an offence.

Similar laws apply elsewhere (e.g. UK Computer Misuse Act 1990, US CFAA).

You may ONLY scan systems you own, or systems for which you hold
[bold]explicit written authorization[/bold] from the owner. The authors accept no
liability for misuse. This tool is detection-only and does not extract data."""

CONFIRM_PHRASE = "I AGREE"


def show_banner(console: Console) -> None:
    console.print(f"[bold cyan]{BANNER}[/bold cyan]", highlight=False)
    console.print(f"  [bold]{TOOL_NAME}[/bold] v{__version__} - ethical SQL injection scanner\n")


def confirm_authorization(console: Console, pre_accepted: bool) -> bool:
    """Show the disclaimer and require an explicit typed confirmation.

    Returns True only if the user typed the exact confirmation phrase
    (or passed --accept-disclaimer for scripted lab runs).
    """
    console.print(Panel(DISCLAIMER, border_style="red", title="WARNING"))
    if pre_accepted:
        console.print("[yellow]Disclaimer accepted via --accept-disclaimer.[/yellow]\n")
        return True
    if not sys.stdin.isatty():
        console.print("[red]No interactive terminal: re-run with --accept-disclaimer "
                      "to confirm you are authorized.[/red]")
        return False
    try:
        answer = input(f"Type '{CONFIRM_PHRASE}' to confirm you are authorized to test the target: ")
    except (EOFError, KeyboardInterrupt):
        console.print()
        return False
    return answer.strip() == CONFIRM_PHRASE
