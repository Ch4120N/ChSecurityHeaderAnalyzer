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
