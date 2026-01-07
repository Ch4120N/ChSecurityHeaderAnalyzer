"""
Utility Functions Module
"""

import os
import sys
import logging
import re
from typing import Dict, Any
from urllib.parse import urlparse
from pathlib import Path

import yaml


def setup_logging(log_level: str = "INFO", suppress_warnings: bool = True) -> logging.Logger:
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
    # Suppress specific warnings if requested
    if suppress_warnings:
        # Suppress urllib3 connection warnings
        logging.getLogger("urllib3").setLevel(logging.ERROR)
        
        # Suppress requests library warnings
        logging.getLogger("requests").setLevel(logging.ERROR)
        
        # Suppress connection pool warnings
        logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)
        
        # Suppress InsecureRequestWarning if SSL verification is disabled
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
    """Get default configuration matching the updated config.yaml"""
    return {
        'security_headers': {
            'required': [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'Referrer-Policy',
                'Permissions-Policy',
                'Set-Cookie',
                'Access-Control-Allow-Origin',
                'Access-Control-Allow-Credentials'
            ],
            'recommended': [
                'Cache-Control',
                'Clear-Site-Data',
                'Cross-Origin-Embedder-Policy',
                'Cross-Origin-Opener-Policy',
                'Cross-Origin-Resource-Policy',
                'X-Permitted-Cross-Domain-Policies',
                'X-Download-Options',
                'Content-Type',
                'X-DNS-Prefetch-Control',
                'Expect-CT',
                'Feature-Policy',
                'Public-Key-Pins',
                'X-Robots-Tag',
                'X-Request-ID'
            ],
            'vulnerable_headers': [
                'Server',
                'X-Powered-By',
                'X-AspNet-Version',
                'X-AspNetMvc-Version',
                'X-Runtime',
                'X-Version',
                'X-Generator',
                'X-Drupal-Cache',
                'X-Pingback',
                'X-Backend-Server',
                'X-Served-By',
                'X-Host',
                'X-Backend',
                'X-Server',
                'X-Engine',
                'X-PHP-Version',
                'X-PHP-Platform',
                'X-Request-Id',
                'X-Cache-Info',
                'X-Cache-Hits',
                'Via',
                'X-Varnish',
                'X-Amz-Cf-Id',
                'X-Amz-Cf-Pop',
                'CF-Ray',
                'CF-Cache-Status',
                'X-Google-Cache-Control',
                'X-Source-Scheme',
                'X-Forwarded-Server',
                'X-Forwarded-Host',
                'X-Forwarded-Proto',
                'X-Original-URL',
                'X-Rewrite-URL',
                'X-Content-Type',
                'X-UA-Compatible',
                'X-Wap-Profile',
                'X-ATT-DeviceId',
                'X-Content-Duration',
                'X-Content-Security-Policy',
                'X-WebKit-CSP',
                'X-Content-Security-Policy-Report-Only',
                'X-Firefox-Security-Policy',
                'X-XSS-Protection'
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
        },
        'vulnerabilities': {
            'missing_headers': {
                'critical': [
                    'Strict-Transport-Security',
                    'Content-Security-Policy',
                    'Set-Cookie'
                ],
                'high': [
                    'X-Frame-Options',
                    'X-Content-Type-Options',
                    'Access-Control-Allow-Origin',
                    'Access-Control-Allow-Credentials'
                ],
                'medium': [
                    'Referrer-Policy',
                    'Permissions-Policy'
                ]
            },
            'weak_configurations': {
                'hsts': {
                    'max_age_minimum': 31536000,
                    'include_subdomains': True,
                    'preload': True
                },
                'csp': {
                    'unsafe_inline': False,
                    'unsafe_eval': False,
                    'https_required': True
                },
                'cookie': {
                    'secure_required': True,
                    'httponly_required': True,
                    'samesite_required': 'Strict'
                },
                'cors': {
                    'wildcard_allowed': False,
                    'credentials_with_wildcard': False,
                    'methods_exposed': ['GET', 'POST', 'HEAD', 'OPTIONS']
                },
                'cache': {
                    'no_store_required': True,
                    'no_cache_required': False,
                    'private_required': True,
                    'must_revalidate_required': True
                }
            }
        },
        'grading': {
            'score_weights': {
                'required_header': 10,
                'recommended_header': 5,
                'vulnerable_header_found': -15,
                'weak_configuration': -5
            },
            'grade_thresholds': {
                'A': 90,
                'B': 75,
                'C': 60,
                'D': 40,
                'F': 0
            }
        },
        'additional_checks': {
            'check_cookie_flags': True,
            'check_csp_directives': True,
            'check_cors_configuration': True,
            'check_hsts_preload_status': False,
            'check_ssl_certificate': True,
            'check_tls_version': True,
            'check_http_methods': True,
            'check_server_banner': True
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