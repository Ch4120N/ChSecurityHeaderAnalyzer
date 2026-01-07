"""
Utility Functions Module
"""

import os
import sys
import logging
import yaml
import re
from typing import Dict, Any
from urllib.parse import urlparse
from pathlib import Path

def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """Setup logging configuration"""
    # Create logs directory if it doesn't exist
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / 'chSecurityHeaderAnalyzer.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    return logging.getLogger(__name__)

def load_config(config_path: str = None) -> Dict[str, Any]:
    """Load configuration from YAML file"""
    if config_path is None:
        # Try to find config file in various locations
        possible_paths = [
            Path("config/config.yaml"),
            Path("/etc/chSecurityHeaderAnalyzer/config.yaml"),
            Path.home() / ".chSecurityHeaderAnalyzer/config.yaml"
        ]
        
        for path in possible_paths:
            if path.exists():
                config_path = str(path)
                break
        else:
            # Use default config
            return get_default_config()
    
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        logging.error(f"Error loading config from {config_path}: {e}")
        return get_default_config()

def get_default_config() -> Dict[str, Any]:
    """Get default configuration"""
    return {
        'security_headers': {
            'required': [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'Referrer-Policy',
                'Permissions-Policy'
            ],
            'recommended': [
                'Cache-Control',
                'Clear-Site-Data',
                'Cross-Origin-Embedder-Policy',
                'Cross-Origin-Opener-Policy',
                'Cross-Origin-Resource-Policy'
            ],
            'vulnerable_headers': [
                'Server',
                'X-Powered-By',
                'X-AspNet-Version',
                'X-AspNetMvc-Version'
            ]
        },
        'scanner': {
            'timeout': 10,
            'max_redirects': 5,
            'user_agent': 'ChSecurityHeaderAnalyzer/1.0',
            'verify_ssl': True,
            'follow_redirects': True,
            'thread_count': 10,
            'rate_limit': 10
        },
        'reporting': {
            'default_output_dir': './reports',
            'formats': ['txt', 'json', 'csv', 'html'],
            'include_timestamp': True,
            'compress_reports': False
        }
    }

def validate_url(url: str) -> bool:
    """Validate URL format"""
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        result = urlparse(url)
        # Check if we have at least scheme and netloc
        if all([result.scheme, result.netloc]):
            # Check if scheme is http or https
            if result.scheme in ['http', 'https']:
                return True
    except Exception:
        pass
    
    return False

def sanitize_filename(filename: str) -> str:
    """Sanitize string to be safe as filename"""
    # Remove invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Remove control characters
    filename = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', filename)
    
    # Limit length
    if len(filename) > 255:
        filename = filename[:255]
    
    return filename

def get_timestamp() -> str:
    """Get current timestamp string"""
    from datetime import datetime
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def create_directory(path: str) -> bool:
    """Create directory if it doesn't exist"""
    try:
        Path(path).mkdir(parents=True, exist_ok=True)
        return True
    except Exception as e:
        logging.error(f"Error creating directory {path}: {e}")
        return False
    
def bytes_to_human_readable(size_bytes: int) -> str:
    """Convert bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"

def is_valid_ip(address: str) -> bool:
    """Check if string is a valid IP address"""
    import ipaddress
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False
    
def get_file_extension(filename: str) -> str:
    """Get file extension from filename"""
    return Path(filename).suffix.lower()

def merge_dicts(dict1: Dict, dict2: Dict) -> Dict:
    """Merge two dictionaries recursively"""
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value
    return result