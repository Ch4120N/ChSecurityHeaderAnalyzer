"""
URL Scanner Module
"""

import requests
import time
from typing import Dict, Optional, Tuple

from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from modules.ui import ConsoleUI

class SecurityScanner:
    def __init__(self, config: Dict):
        self.config = config
        self.session = self._create_session()
        self.ui = ConsoleUI()
        
    def _create_session(self) -> requests.Session:
        """Create a configured requests session"""
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=100,
            pool_maxsize=100
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set default headers
        session.headers.update({
            'User-Agent': self.config['scanner']['user_agent'],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1'
        })
        
        return session

    def scan_url(self, url: str) -> Optional[Dict[str, str]]:
        """Scan a URL and return its headers"""
        try:
            # Ensure URL has scheme
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Rate limiting
            time.sleep(1 / self.config['scanner']['rate_limit'])
            
            # Make request
            response = self.session.get(
                url,
                timeout=self.config['scanner']['timeout'],
                verify=self.config['scanner']['verify_ssl'],
                allow_redirects=self.config['scanner']['follow_redirects']
            )
            
            # Get all headers (case-insensitive)
            headers = {}
            
            # Handle Set-Cookie headers specially (they can have multiple values)
            set_cookie_values = []
            for key, value in response.headers.items():
                key_lower = key.lower()
                
                if key_lower == 'set-cookie':
                    set_cookie_values.append(value)
                else:
                    headers[key_lower] = value
            
            # Store Set-Cookie as list if multiple, otherwise as single value
            if set_cookie_values:
                headers['set-cookie'] = set_cookie_values if len(set_cookie_values) > 1 else set_cookie_values[0]
            
            # Add response info
            headers['_status_code'] = str(response.status_code)
            headers['_url'] = response.url
            headers['_content_type'] = response.headers.get('Content-Type', '')
            headers['_server'] = response.headers.get('Server', '')
            headers['_response_time'] = str(response.elapsed.total_seconds())
            
            return headers
            
        except requests.exceptions.RequestException as e:
            self.ui.print_error("Request failed! Please check your connection/Or use VPN")
        except Exception as e:
            self.ui.print_error("Scan failed! Please check your connection/Or use VPN")

    def scan_multiple(self, urls: list) -> Dict[str, Optional[Dict[str, str]]]:
        """Scan multiple URLs (to be used with threading)"""
        results = {}
        for url in urls:
            try:
                results[url] = self.scan_url(url)
            except Exception as e:
                results[url] = None
        return results