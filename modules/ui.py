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
            'header': Fore.BLUE + Style.BRIGHT,
            'url': Fore.MAGENTA
        }