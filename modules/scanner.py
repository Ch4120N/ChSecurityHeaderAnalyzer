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
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Add response info
            headers['_status_code'] = str(response.status_code)
            headers['_url'] = response.url
            headers['_content_type'] = response.headers.get('Content-Type', '')
            headers['_server'] = response.headers.get('Server', '')
            
            return headers
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Request failed: {str(e)}")
        except Exception as e:
            raise Exception(f"Scan failed: {str(e)}")
    
    def scan_multiple(self, urls: list) -> Dict[str, Optional[Dict[str, str]]]:
        """Scan multiple URLs (to be used with threading)"""
        results = {}
        for url in urls:
            try:
                results[url] = self.scan_url(url)
            except Exception as e:
                results[url] = None
        return results