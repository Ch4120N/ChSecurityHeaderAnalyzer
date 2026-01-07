"""
Header Analysis Module
"""

import re
from typing import Dict, List, Tuple, Any
from datetime import datetime


class HeaderAnalyzer:
    def __init__(self, config: Dict):
        self.config = config
        self.required_headers = config['security_headers']['required']
        self.recommended_headers = config['security_headers']['recommended']
        self.vulnerable_headers = config['security_headers']['vulnerable_headers']
    
    