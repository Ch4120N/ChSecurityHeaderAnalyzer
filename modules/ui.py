"""
User Interface Module
"""

import sys
from typing import Dict, Any, List
from datetime import datetime
from colorama import init, Fore, Style, Back
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich.layout import Layout
from rich.align import Align
from rich.text import Text

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class ConsoleUI:
    def __init__(self):
        self.console = Console()
        self.colors = {
            'info': Fore.CYAN,
            'success': Fore.GREEN,
            'warning': Fore.YELLOW,
            'error': Fore.RED,
            'critical': Fore.RED + Style.BRIGHT,
            'header': Fore.RED + Style.BRIGHT,
            'url': Fore.MAGENTA
        }
    
    def display_header(self):
        """Display tool header"""
        centered_banner = Align.center(fr"""[bold red]
   ___ _     __                                _            _               _                    
  / __\ |__ / _\ ___  ___  /\  /\___  __ _  __| | ___ _ __ /_\  _ __   __ _| |_   _ _______ _ __ 
 / /  | '_ \\ \ / _ \/ __|/ /_/ / _ \/ _` |/ _` |/ _ \ '__//_\\| '_ \ / _` | | | | |_  / _ \ '__|
/ /___| | | |\ \  __/ (__/ __  /  __/ (_| | (_| |  __/ | /  _  \ | | | (_| | | |_| |/ /  __/ |   
\____/|_| |_\__/\___|\___\/ /_/ \___|\__,_|\__,_|\___|_| \_/ \_/_| |_|\__,_|_|\__, /___\___|_|   
                                                                              |___/              [/bold red]
        """)
        self.console.print(centered_banner)
        self.console.print("[bold white]Owned By [/][bold blue][[/] [bold red]Ch4120N[/] [bold blue]][/]", justify="center")
        self.console.print("[bold blue]GitHub.com/Ch4120N[/]", justify='center')
    