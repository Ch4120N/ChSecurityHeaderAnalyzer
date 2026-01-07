"""
URL Scanner Module
"""

import requests
import time
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry



class SecurityScanner:
    def __init__(self, config: Dict):
        self.config = config
        self.session = self._create_session()
    
    