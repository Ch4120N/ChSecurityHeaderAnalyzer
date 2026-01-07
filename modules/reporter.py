"""
Report Generator Module
"""

import json
import csv
import os
from typing import Dict, List, Any
from datetime import datetime
import pandas as pd
from jinja2 import Template


class ReportGenerator:
    def __init__(self, config: Dict):
        self.config = config
        self.output_dir = config['reporting']['default_output_dir']
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)

