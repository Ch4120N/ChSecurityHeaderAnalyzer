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