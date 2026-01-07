#!/usr/bin/env python3

#  ____  _____  _    _  ____  ____  ____  ____     ____  _  _     ___  _   _  __  __  ___   ___  _  _ 
# (  _ \(  _  )( \/\/ )( ___)(  _ \( ___)(  _ \   (  _ \( \/ )   / __)( )_( )/. |/  )(__ \ / _ \( \( )
#  )___/ )(_)(  )    (  )__)  )   / )__)  )(_) )   ) _ < \  /   ( (__  ) _ ((_  _))(  / _/( (_) ))  ( 
# (__)  (_____)(__/\__)(____)(_)\_)(____)(____/   (____/ (__)    \___)(_) (_) (_)(__)(____)\___/(_)\_)
# 

# Project   : ChSecurityHeaderAnalyzer - Comprehensive Security Header Analysis Tool
# Owner     : Ch4120N
# Version   : 1.0.0
# Repo URL  : https://github.com/Ch4120N/ChSecurityHeaderAnalyzer

import argparse
import sys
import os
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any
from datetime import datetime

from modules.scanner import SecurityScanner
from modules.analyzer import HeaderAnalyzer
from modules.reporter import ReportGenerator
from modules.ui import ConsoleUI, ProgressTracker
from modules.utils import setup_logging, load_config, validate_url



class ChSecurityHeaderAnalyzer:
    def __init__(self):
        self.config = load_config()
        self.logger = setup_logging()
        self.scanner = SecurityScanner(self.config)
        self.analyzer = HeaderAnalyzer(self.config)
        self.reporter = ReportGenerator(self.config)
        self.ui = ConsoleUI()
    
