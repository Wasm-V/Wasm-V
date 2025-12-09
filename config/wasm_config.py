#!/usr/bin/env python3
"""
FILENAME: config/wasm_config.py
DESCRIPTION: Configuration settings for WASM vulnerability analysis
"""

import os
from pathlib import Path
from dotenv import load_dotenv

class WasmConfig:
    """Configuration class for WASM vulnerability analysis"""
    
    def __init__(self):
        # Load environment variables from .env file if it exists
        env_file = Path(__file__).parent.parent / '.env'
        if env_file.exists():
            load_dotenv(env_file)
        
        # Base directories
        self.BASE_DIR = Path(__file__).parent.parent
        self.DATA_DIR = self.BASE_DIR / "data"
        self.RAW_DIR = self.DATA_DIR / "raw"
        self.PROCESSED_DIR = self.DATA_DIR / "processed"
        self.COMPILED_DIR = self.DATA_DIR / "compiled"
        
        # Create directories
        for directory in [self.DATA_DIR, self.RAW_DIR, self.PROCESSED_DIR, self.COMPILED_DIR]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Processing limits
        self.MAX_WORKERS = int(os.environ.get('WASM_MAX_WORKERS', 20))  # Increased from 8
        self.CVE_LOOKUP_WORKERS = int(os.environ.get('WASM_CVE_WORKERS', 20))  # New setting
        self.MAX_VULNERABILITIES = self._get_env_int('WASM_MAX_VULNERABILITIES', None)
        self.MAX_REPOSITORIES = self._get_env_int('WASM_MAX_REPOSITORIES', None)
        self.MAX_ECOSYSTEMS = self._get_env_int('WASM_MAX_ECOSYSTEMS', None)
        
        # API rate limiting (seconds)
        self.API_DELAYS = {
            'osv': float(os.environ.get('WASM_OSV_DELAY', 0.1)),
            'github': float(os.environ.get('WASM_GITHUB_DELAY', 0.3)),
            'nvd': float(os.environ.get('WASM_NVD_DELAY', 1.5)),
            'repo_search': float(os.environ.get('WASM_REPO_DELAY', 0.4))
        }
        
        # Compilation settings
        self.COMPILATION_TIMEOUT_MINUTES = int(os.environ.get('WASM_COMPILATION_TIMEOUT', 10))
        
        # API tokens
        self.GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')
        self.NVD_API_KEY = os.environ.get('NVD_API_KEY')
        
        # Pipeline settings
        self.MIN_PROJECT_CONFIDENCE = float(os.environ.get('WASM_MIN_CONFIDENCE', 0.7))
        self.ENABLE_REPOSITORY_CLONING = os.environ.get('WASM_ENABLE_CLONING', 'true').lower() == 'true'
        
    def _get_env_int(self, key: str, default: int = None) -> int:
        """Get integer environment variable"""
        value = os.environ.get(key)
        if value is None:
            return default
        try:
            return int(value)
        except ValueError:
            return default
    
    def get_chunk_size_for_items(self, item_count: int) -> int:
        """Get appropriate chunk size for parallel processing"""
        if item_count < 100:
            return 10
        elif item_count < 1000:
            return 50
        else:
            return 100

# Global configuration instance
CONFIG = WasmConfig()
