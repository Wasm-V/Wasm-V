#!/usr/bin/env python3
"""
FILENAME: discovery/wasm_project_discovery.py
DESCRIPTION: Discovery engine for projects known to compile to WASM
"""

import requests
import json
import time
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import click
from tqdm import tqdm
import re
from urllib.parse import urlparse, parse_qs
import base64

# Add config to path
sys.path.append(str(Path(__file__).parent.parent))
from config.wasm_config import CONFIG

@dataclass
class WasmProject:
    """Represents a project known to compile to WASM"""
    name: str
    ecosystem: str
    repo_url: str
    language: str
    wasm_confirmed: bool
    confidence_score: float
    discovery_method: str
    metadata: Dict[str, Any]
    
    def to_dict(self):
        return asdict(self)

class WasmProjectDiscovery:
    """Main discovery engine for WASM-capable projects"""
    
    def __init__(self, output_dir: str = None):
        self.output_dir = Path(output_dir) if output_dir else Path("data/wasm_projects")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # GitHub API setup
        self.github_token = self._get_github_token()
        self.github_headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'wasm-cve-collector'
        }
        if self.github_token:
            self.github_headers['Authorization'] = f'token {self.github_token}'
        
        # Rate limiting
        self.request_delay = 0.3  # seconds between requests (reduced from 1.0)
        self.last_request_time = 0
        self.rate_lock = threading.Lock()
        
        # Results tracking
        self.discovered_projects = []
        self.discovery_stats = {
            'rust_projects': 0,
            'go_projects': 0,
            'cpp_projects': 0,
            'total_unique': 0,
            'api_calls_made': 0,
            'discovery_time': 0
        }
    
    def _get_github_token(self) -> Optional[str]:
        """Get GitHub token from environment or config"""
        import os
        token = os.environ.get('GITHUB_TOKEN') or getattr(CONFIG, 'GITHUB_TOKEN', None)
        if not token:
            click.echo("Warning: No GitHub token found. API rate limits will be restrictive.")
        return token
    
    def _rate_limited_request(self, url: str, **kwargs) -> requests.Response:
        """Make rate-limited HTTP request"""
        with self.rate_lock:
            # Ensure minimum delay between requests
            elapsed = time.time() - self.last_request_time
            if elapsed < self.request_delay:
                time.sleep(self.request_delay - elapsed)
            
            self.last_request_time = time.time()
            self.discovery_stats['api_calls_made'] += 1
            
            return requests.get(url, **kwargs)
    
    def discover_all_wasm_projects(self) -> List[WasmProject]:
        """Discover all WASM-capable projects from multiple sources"""
        click.echo("Starting comprehensive WASM project discovery...")
        start_time = time.time()
        
        all_projects = []
        
        # Rust projects
        click.echo("Discovering Rust WASM projects...")
        rust_projects = self.discover_rust_wasm_projects()
        all_projects.extend(rust_projects)
        self.discovery_stats['rust_projects'] = len(rust_projects)
        
        # Go projects
        click.echo("Discovering Go WASM projects...")
        go_projects = self.discover_go_wasm_projects()
        all_projects.extend(go_projects)
        self.discovery_stats['go_projects'] = len(go_projects)
        
        # C/C++ projects using Emscripten
        click.echo("Discovering C/C++ Emscripten projects...")
        cpp_projects = self.discover_emscripten_projects()
        all_projects.extend(cpp_projects)
        self.discovery_stats['cpp_projects'] = len(cpp_projects)
        
        # Deduplicate by repository URL
        unique_projects = self._deduplicate_projects(all_projects)
        
        self.discovery_stats['total_unique'] = len(unique_projects)
        self.discovery_stats['discovery_time'] = time.time() - start_time
        
        self.discovered_projects = unique_projects
        self._save_discovered_projects(unique_projects)
        self._print_discovery_summary()
        
        return unique_projects
    
    def discover_rust_wasm_projects(self) -> List[WasmProject]:
        """Discover Rust projects with WASM support"""
        rust_projects = []
        
        # Method 1: Search crates.io for WASM-related dependencies
        wasm_crates = self._search_crates_io_wasm_deps()
        rust_projects.extend(wasm_crates)
        
        # Method 2: GitHub search for Rust + WASM
        github_rust = self._github_search_rust_wasm()
        rust_projects.extend(github_rust)
        
        # Method 3: Known WASM framework crates
        framework_projects = self._discover_wasm_framework_projects()
        rust_projects.extend(framework_projects)
        
        return rust_projects
    
    def _search_crates_io_wasm_deps(self) -> List[WasmProject]:
        """Search crates.io for crates with WASM dependencies"""
        wasm_projects = []
        
        # Key WASM-related crates to search for dependents
        wasm_dependencies = [
            'wasm-bindgen',
            'web-sys', 
            'js-sys',
            'wasm-pack',
            'console_error_panic_hook',
            'wee_alloc'
        ]
        
        for dep in wasm_dependencies:
            click.echo(f"  Searching crates.io for {dep} dependents...")
            
            try:
                # Search for crates that depend on this WASM crate
                url = f"https://crates.io/api/v1/crates?q={dep}&per_page=100"
                response = self._rate_limited_request(url)
                
                if response.status_code == 200:
                    data = response.json()
                    crates = data.get('crates', [])
                    
                    for crate in crates:
                        # Fix: Check if crate is a dict before accessing attributes
                        if not isinstance(crate, dict):
                            continue
                            
                        repo_url = crate.get('repository')
                        if repo_url and 'github.com' in repo_url:
                            project = WasmProject(
                                name=crate['name'],
                                ecosystem='crates.io',
                                repo_url=repo_url,
                                language='rust',
                                wasm_confirmed=True,
                                confidence_score=0.9,
                                discovery_method=f'crates.io_{dep}_search',
                                metadata={
                                    'downloads': crate.get('downloads', 0),
                                    'description': crate.get('description', ''),
                                    'categories': crate.get('categories', []),
                                    'keywords': crate.get('keywords', []),
                                    'wasm_dependency': dep
                                }
                            )
                            wasm_projects.append(project)
                
                time.sleep(0.5)  # Be nice to crates.io
                
            except Exception as e:
                click.echo(f"    Error searching for {dep}: {e}")
        
        return wasm_projects
    
    def _get_crate_detail(self, crate_name: str) -> Optional[Dict]:
        """Get detailed information about a crate"""
        try:
            url = f"https://crates.io/api/v1/crates/{crate_name}"
            response = self._rate_limited_request(url)
            
            if response.status_code == 200:
                data = response.json()
                # Add some validation
                if isinstance(data, dict) and 'crate' in data:
                    return data
                else:
                    click.echo(f"    Unexpected crate data format for {crate_name}")
                    return None
        except Exception as e:
            click.echo(f"    Error getting crate detail for {crate_name}: {e}")
        
        return None
    
    def _is_wasm_relevant_crate(self, crate_detail: Optional[Dict]) -> bool:
        """Check if a crate is relevant for WASM compilation"""
        if not crate_detail or not isinstance(crate_detail, dict):
            return False
        
        crate = crate_detail.get('crate', {})
        if not isinstance(crate, dict):
            return False
        
        # Check categories
        categories = crate.get('categories', [])
        if isinstance(categories, list):
            category_names = [cat.get('category', '') if isinstance(cat, dict) else str(cat) for cat in categories]
            wasm_categories = ['web-programming', 'wasm', 'no-std', 'parsing', 'games']
            
            if any(cat in wasm_categories for cat in category_names):
                return True
        
        # Check keywords
        keywords = crate.get('keywords', [])
        if isinstance(keywords, list):
            keyword_names = [kw.get('keyword', '') if isinstance(kw, dict) else str(kw) for kw in keywords]
            wasm_keywords = ['wasm', 'web', 'webassembly', 'browser', 'no-std']
            
            if any(kw in wasm_keywords for kw in keyword_names):
                return True
        
        # Check description
        description = str(crate.get('description', '') + ' ' + crate.get('documentation', '')).lower()
        wasm_terms = ['wasm', 'webassembly', 'browser', 'web application', 'javascript']
        
        if any(term in description for term in wasm_terms):
            return True
        
        return False
    
    def _github_search_rust_wasm(self) -> List[WasmProject]:
        """Search GitHub for Rust projects with WASM indicators"""
        rust_projects = []
        
        search_queries = [
            'language:rust wasm-bindgen in:file',
            'language:rust "wasm-pack" in:file',
            'language:rust "web-sys" in:file',
            'language:rust "target wasm32" in:file',
            'language:rust "[target.wasm32-unknown-unknown]" in:file'
        ]
        
        for query in search_queries:
            try:
                projects = self._github_code_search(query, max_results=50)
                rust_projects.extend(projects)
                time.sleep(2)  # Rate limiting
            except Exception as e:
                click.echo(f"    Error in GitHub search '{query[:30]}...': {e}")
        
        return rust_projects
    
    def _discover_wasm_framework_projects(self) -> List[WasmProject]:
        """Discover projects using known WASM frameworks"""
        framework_projects = []
        
        # Known WASM frameworks and their ecosystem projects
        frameworks = {
            'yew': 'https://api.github.com/search/repositories?q=yew+language:rust&per_page=50',
            'seed': 'https://api.github.com/search/repositories?q=seed+language:rust&per_page=50',
            'percy': 'https://api.github.com/search/repositories?q=percy+language:rust&per_page=50',
            'leptos': 'https://api.github.com/search/repositories?q=leptos+language:rust&per_page=50'
        }
        
        for framework, search_url in frameworks.items():
            try:
                response = self._rate_limited_request(search_url, headers=self.github_headers)
                
                if response.status_code == 200:
                    data = response.json()
                    repos = data.get('items', [])
                    
                    for repo in repos[:20]:  # Limit to top 20 per framework
                        project = WasmProject(
                            name=repo['name'],
                            ecosystem='crates.io',
                            repo_url=repo['html_url'],
                            language='rust',
                            wasm_confirmed=True,
                            confidence_score=0.95,
                            discovery_method=f'framework_{framework}',
                            metadata={
                                'stars': repo.get('stargazers_count', 0),
                                'description': repo.get('description', ''),
                                'framework': framework,
                                'updated_at': repo.get('updated_at')
                            }
                        )
                        framework_projects.append(project)
                
                time.sleep(2)
                
            except Exception as e:
                click.echo(f"    Error discovering {framework} projects: {e}")
        
        return framework_projects
    
    def discover_go_wasm_projects(self) -> List[WasmProject]:
        """Discover Go projects with WASM support"""
        go_projects = []
        
        # GitHub searches for Go WASM indicators
        search_queries = [
            'language:go "//go:build js,wasm" in:file',
            'language:go "GOOS=js GOARCH=wasm" in:file',
            'language:go "syscall/js" in:file',
            'language:go "js.Global()" in:file'
        ]
        
        for query in search_queries:
            try:
                projects = self._github_code_search(query, max_results=30)
                go_projects.extend(projects)
                time.sleep(2)
            except Exception as e:
                click.echo(f"    Error in Go GitHub search: {e}")
        
        return go_projects
    
    def discover_emscripten_projects(self) -> List[WasmProject]:
        """Discover C/C++ projects using Emscripten"""
        cpp_projects = []
        
        # GitHub searches for Emscripten indicators
        search_queries = [
            'language:c "emcc" in:file',
            'language:cpp "emcc" in:file', 
            'language:c "emcmake" in:file',
            'language:cpp "emcmake" in:file',
            '"emscripten" language:c',
            '"emscripten" language:cpp'
        ]
        
        for query in search_queries:
            try:
                projects = self._github_code_search(query, max_results=20)
                cpp_projects.extend(projects)
                time.sleep(2)
            except Exception as e:
                click.echo(f"    Error in C/C++ GitHub search: {e}")
        
        return cpp_projects
    
    def _github_code_search(self, query: str, max_results: int = 50) -> List[WasmProject]:
        """Perform GitHub code search and extract repository information"""
        projects = []
        
        try:
            # GitHub code search API
            search_url = f"https://api.github.com/search/code?q={query}&per_page={min(max_results, 100)}"
            response = self._rate_limited_request(search_url, headers=self.github_headers)
            
            if response.status_code == 200:
                data = response.json()
                items = data.get('items', [])
                
                # Extract unique repositories
                seen_repos = set()
                
                for item in items:
                    repo = item.get('repository', {})
                    repo_url = repo.get('html_url', '')
                    
                    if repo_url and repo_url not in seen_repos:
                        seen_repos.add(repo_url)
                        
                        # Determine language
                        language = repo.get('language', '').lower()
                        if not language:
                            if 'language:rust' in query:
                                language = 'rust'
                            elif 'language:go' in query:
                                language = 'go'
                            elif 'language:c' in query:
                                language = 'c'
                            elif 'language:cpp' in query:
                                language = 'c++'
                        
                        # Determine ecosystem
                        ecosystem = self._determine_ecosystem(language, repo_url)
                        
                        project = WasmProject(
                            name=repo.get('name', ''),
                            ecosystem=ecosystem,
                            repo_url=repo_url,
                            language=language,
                            wasm_confirmed=True,
                            confidence_score=0.8,
                            discovery_method='github_code_search',
                            metadata={
                                'stars': repo.get('stargazers_count', 0),
                                'description': repo.get('description', ''),
                                'updated_at': repo.get('updated_at', ''),
                                'search_query': query,
                                'file_path': item.get('path', '')
                            }
                        )
                        projects.append(project)
            
            elif response.status_code == 403:
                click.echo("    GitHub API rate limit reached")
            else:
                click.echo(f"    GitHub search failed: {response.status_code}")
        
        except Exception as e:
            click.echo(f"    GitHub search error: {e}")
        
        return projects
    
    def _determine_ecosystem(self, language: str, repo_url: str) -> str:
        """Determine the package ecosystem for a project"""
        if language == 'rust':
            return 'crates.io'
        elif language == 'go':
            return 'go_modules'
        elif language in ['c', 'c++', 'cpp']:
            return 'native'
        else:
            return 'unknown'
    
    def _deduplicate_projects(self, projects: List[WasmProject]) -> List[WasmProject]:
        """Remove duplicate projects based on repository URL"""
        seen_urls = set()
        unique_projects = []
        
        for project in projects:
            normalized_url = project.repo_url.rstrip('/').lower()
            
            if normalized_url not in seen_urls:
                seen_urls.add(normalized_url)
                unique_projects.append(project)
        
        return unique_projects
    
    def _save_discovered_projects(self, projects: List[WasmProject]):
        """Save discovered projects to JSON file"""
        output_file = self.output_dir / "discovered_wasm_projects.json"
        
        data = {
            "discovery_timestamp": time.time(),
            "discovery_stats": self.discovery_stats,
            "total_projects": len(projects),
            "projects": [project.to_dict() for project in projects]
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        click.echo(f"Saved {len(projects)} discovered projects to {output_file}")
    
    def _print_discovery_summary(self):
        """Print summary of discovery results"""
        stats = self.discovery_stats
        
        click.echo("\nWASM Project Discovery Summary:")
        click.echo("=" * 50)
        click.echo(f"Rust projects: {stats['rust_projects']}")
        click.echo(f"Go projects: {stats['go_projects']}")
        click.echo(f"C/C++ projects: {stats['cpp_projects']}")
        click.echo(f"Total unique: {stats['total_unique']}")
        click.echo(f"API calls made: {stats['api_calls_made']}")
        click.echo(f"Discovery time: {stats['discovery_time']:.2f}s")
        
        if stats['total_unique'] > 0:
            click.echo(f"\nTop projects by confidence:")
            top_projects = sorted(self.discovered_projects, key=lambda x: x.confidence_score, reverse=True)[:5]
            for project in top_projects:
                click.echo(f"  {project.name} ({project.language}) - {project.confidence_score:.2f}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Discover WASM-capable projects')
    parser.add_argument('--output', default='data/wasm_projects', help='Output directory')
    parser.add_argument('--rust-only', action='store_true', help='Discover only Rust projects')
    parser.add_argument('--go-only', action='store_true', help='Discover only Go projects')
    parser.add_argument('--cpp-only', action='store_true', help='Discover only C/C++ projects')
    
    args = parser.parse_args()
    
    discovery = WasmProjectDiscovery(args.output)
    
    if args.rust_only:
        projects = discovery.discover_rust_wasm_projects()
    elif args.go_only:
        projects = discovery.discover_go_wasm_projects()
    elif args.cpp_only:
        projects = discovery.discover_emscripten_projects()
    else:
        projects = discovery.discover_all_wasm_projects()
    
    click.echo(f"Discovery complete: {len(projects)} WASM-capable projects found")
