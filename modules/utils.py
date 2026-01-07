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