"""
Utility Functions Module - Excellent Edition
"""

import os, sys, logging, re, yaml
from typing import Dict, Any
from urllib.parse import urlparse
from pathlib import Path
from datetime import datetime

def setup_logging(log_level: str = "INFO", suppress_warnings: bool = True) -> logging.Logger:
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / 'chSecurityHeaderAnalyzer.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    if suppress_warnings:
        logging.getLogger("urllib3").setLevel(logging.ERROR)
        logging.getLogger("requests").setLevel(logging.ERROR)
        logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return logging.getLogger(__name__)

def load_config(config_path: str = None) -> Dict[str, Any]:
    if config_path is None:
        possible = [
            Path("config/config.yaml"),
            Path("/etc/chSecurityHeaderAnalyzer/config.yaml"),
            Path.home() / ".chSecurityHeaderAnalyzer/config.yaml"
        ]
        for p in possible:
            if p.exists():
                config_path = str(p)
                break
        else:
            return get_default_config()
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception:
        logging.error(f"Failed to load config from {config_path}, using defaults")
        return get_default_config()

def get_default_config() -> Dict[str, Any]:
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
                'Cross-Origin-Embedder-Policy',
                'Cross-Origin-Opener-Policy',
                'Cross-Origin-Resource-Policy',
                'X-DNS-Prefetch-Control',
                'X-Robots-Tag',
                'Clear-Site-Data',
                'Reporting-Endpoints'
            ],
            'deprecated': [
                'Expect-CT',
                'Public-Key-Pins',
                'Feature-Policy',
                'X-Download-Options',
                'X-Permitted-Cross-Domain-Policies'
            ],
            'vulnerable': [
                'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version',
                'X-Runtime', 'X-Version', 'X-Generator', 'X-Drupal-Cache', 'X-Pingback',
                'X-Engine', 'X-PHP-Version', 'X-PHP-Platform', 'X-Request-Id',
                'X-Cache-Info', 'X-Cache-Hits', 'X-Backend-Server', 'X-Served-By',
                'X-Host', 'X-Backend', 'X-Server', 'X-Content-Duration', 'X-Source-Scheme',
                'X-Original-URL', 'X-Rewrite-URL', 'X-Content-Type', 'X-UA-Compatible',
                'X-Wap-Profile', 'X-ATT-DeviceId'
            ],
            'infrastructure': [
                'Via', 'X-Varnish', 'X-Amz-Cf-Id', 'X-Amz-Cf-Pop', 'CF-Ray',
                'CF-Cache-Status', 'X-Google-Cache-Control', 'X-Forwarded-Server',
                'X-Forwarded-Host', 'X-Forwarded-Proto', 'X-Firefox-Security-Policy',
                'X-WebKit-CSP', 'X-Content-Security-Policy', 'X-Content-Security-Policy-Report-Only',
                'X-Request-Id'
            ]
        },
        'scanner': {
            'timeout': 10, 'max_redirects': 5,
            'user_agent': 'ChSecurityHeaderAnalyzer/2.0',
            'verify_ssl': True, 'follow_redirects': True,
            'thread_count': 10, 'rate_limit': 10
        },
        'reporting': {
            'default_output_dir': './reports',
            'formats': ['txt', 'json', 'csv', 'html'],
            'include_timestamp': True,
            'compress_reports': False
        },
        'vulnerabilities': {
            'missing_headers': {
                'critical': ['Strict-Transport-Security', 'Content-Security-Policy'],
                'high': ['X-Frame-Options', 'X-Content-Type-Options'],
                'medium': ['Referrer-Policy', 'Permissions-Policy']
            },
            'weak_configurations': {
                'hsts': {'max_age_minimum': 31536000, 'include_subdomains': True, 'preload': True},
                'csp': {'unsafe_inline': False, 'unsafe_eval': False, 'https_required': True},
                'cookie': {'secure_required': True, 'httponly_required': True, 'samesite_required': 'Lax'},
                'cors': {
                    'wildcard_allowed': False,
                    'credentials_with_wildcard': False,
                    'methods_exposed': ['GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'DELETE']
                },
                'cache': {
                    'no_store_required': False,
                    'no_cache_required': False,
                    'private_required': False,
                    'must_revalidate_required': False
                }
            }
        },
        'grading': {
            'missing_critical': -10,
            'missing_high': -7,
            'missing_medium': -4,
            'recommended_missing': -2,
            'vulnerable_header_found': -8,
            'infrastructure_header_found': 0,
            'deprecated_header_found': -2,
            'weak_configuration': -5,
            'bonus_present_required': 3,
            'bonus_present_recommended': 2,
            'bonus_strong_csp': 10,
            'bonus_strong_hsts': 10,
            'grade_thresholds': {'A': 85, 'B': 70, 'C': 55, 'D': 35, 'F': 0}
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
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']
    except Exception:
        return False

def sanitize_filename(filename: str) -> str:
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    filename = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', filename)
    return filename[:255]

def get_timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def create_directory(path: str) -> bool:
    try:
        Path(path).mkdir(parents=True, exist_ok=True)
        return True
    except Exception:
        return False