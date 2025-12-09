#!/usr/bin/env python3
"""
FILENAME: lookup/project_cve_lookup.py
DESCRIPTION: CVE lookup engine for known WASM-capable projects
"""

import requests
import json
import time
import sys
import re
import hashlib
import pickle
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import click
from tqdm import tqdm
from urllib.parse import urlparse

# Add paths for imports
sys.path.append(str(Path(__file__).parent.parent))
from config.wasm_config import CONFIG
from discovery.wasm_project_discovery import WasmProject

@dataclass
class ProjectCVE:
    """CVE associated with a WASM-capable project"""
    cve_id: str
    advisory_id: str
    source_project: WasmProject
    title: str
    description: str
    severity: str
    severity_score: float
    published_date: str
    affected_versions: List[str]
    fixed_versions: List[str]
    repository_url: str
    vulnerable_commit: Optional[str]
    fixed_commit: Optional[str]
    cwe_ids: List[str]
    references: List[str]
    wasm_compilation_confirmed: bool
    metadata: Dict[str, Any]
    
    def to_dict(self):
        result = asdict(self)
        result['source_project'] = self.source_project.to_dict()
        return result

class ProjectCVELookup:
    """Main CVE lookup engine for WASM projects"""
    
    def __init__(self, osv_scraper=None, output_dir: str = None):
        self.output_dir = Path(output_dir) if output_dir else Path("data/project_cves")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Import OSV scraper
        self.osv_scraper = osv_scraper
        
        # GitHub API setup
        self.github_token = self._get_github_token()
        self.github_headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'wasm-cve-lookup'
        }
        if self.github_token:
            self.github_headers['Authorization'] = f'token {self.github_token}'
        
        # API-specific rate limiting (configurable)
        self.api_delays = getattr(CONFIG, 'API_DELAYS', {
            'osv': 0.1,      # OSV is more permissive
            'github': 0.3,   # GitHub allows 5000/hour with token
            'nvd': 1.5,      # NVD is strictest  
            'repo_search': 0.4
        })
        self.last_request_times = {}
        self.rate_locks = {api: threading.Lock() for api in self.api_delays}
        
        # Results tracking
        self.lookup_stats = {
            'projects_processed': 0,
            'total_cves_found': 0,
            'osv_lookups': 0,
            'github_lookups': 0,
            'nvd_lookups': 0,
            'api_calls_made': 0,
            'lookup_time': 0
        }
        
        # Cache for API responses (persistent)
        self.cache_file = self.output_dir / ".cve_cache.pkl"
        self.osv_cache = {}
        self.github_cache = {}
        self._load_persistent_cache()
        
        # Skip low-value searches
        self.common_names = {'test', 'demo', 'example', 'hello', 'simple', 'sample', 'tutorial'}
    
    def _get_github_token(self) -> Optional[str]:
        """Get GitHub token from environment or config"""
        import os
        return os.environ.get('GITHUB_TOKEN') or getattr(CONFIG, 'GITHUB_TOKEN', None)
    
    def _load_persistent_cache(self):
        """Load cached API responses from disk"""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'rb') as f:
                    cache_data = pickle.load(f)
                    self.osv_cache = cache_data.get('osv', {})
                    self.github_cache = cache_data.get('github', {})
                    click.echo(f"Loaded {len(self.osv_cache)} OSV + {len(self.github_cache)} GitHub cached responses")
        except Exception as e:
            click.echo(f"Warning: Could not load cache: {e}")
            self.osv_cache = {}
            self.github_cache = {}
    
    def _save_persistent_cache(self):
        """Save cached API responses to disk"""
        try:
            cache_data = {
                'osv': self.osv_cache,
                'github': self.github_cache,
                'timestamp': time.time()
            }
            with open(self.cache_file, 'wb') as f:
                pickle.dump(cache_data, f)
        except Exception as e:
            click.echo(f"Warning: Could not save cache: {e}")
    
    def _rate_limited_request(self, url: str, api_type: str = 'github', **kwargs) -> requests.Response:
        """Make rate-limited HTTP request with API-specific delays"""
        lock = self.rate_locks.get(api_type, self.rate_locks['github'])
        delay = self.api_delays.get(api_type, 0.5)
        
        with lock:
            last_time = self.last_request_times.get(api_type, 0)
            elapsed = time.time() - last_time
            if elapsed < delay:
                time.sleep(delay - elapsed)
            
            self.last_request_times[api_type] = time.time()
            self.lookup_stats['api_calls_made'] += 1
            
            return requests.get(url, **kwargs)
        
    def _deduplicate_cves_by_project(self, cves: List[ProjectCVE]) -> List[ProjectCVE]:
        """Keep only one CVE per project (the highest severity one)"""
        project_cves = {}
        
        for cve in cves:
            project_key = cve.source_project.repo_url
            
            if project_key not in project_cves:
                project_cves[project_key] = cve
            else:
                # Keep the CVE with higher severity score
                if cve.severity_score > project_cves[project_key].severity_score:
                    project_cves[project_key] = cve
        
        unique_cves = list(project_cves.values())
        click.echo(f"Deduplicated {len(cves)} CVEs to {len(unique_cves)} unique projects")
        return unique_cves
    
    def find_cves_for_projects(self, projects: List[WasmProject]) -> List[ProjectCVE]:
        """Find CVEs for multiple WASM projects"""
        click.echo(f"Looking up CVEs for {len(projects)} WASM-capable projects...")
        start_time = time.time()
        
        all_cves = []
        cve_lock = threading.Lock()
        
        def process_project(project):
            try:
                project_cves = self.find_cves_for_project(project)
                
                with cve_lock:
                    all_cves.extend(project_cves)
                    self.lookup_stats['projects_processed'] += 1
                    
                    if project_cves:
                        click.echo(f"  Found {len(project_cves)} CVEs for {project.name}")
                
                return len(project_cves)
                
            except Exception as e:
                click.echo(f"  Error processing {project.name}: {e}")
                return 0
        
        # Process projects in parallel
        max_workers = min(getattr(CONFIG, 'CVE_LOOKUP_WORKERS', 20), len(projects))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(process_project, project) for project in projects]
            
            for future in tqdm(as_completed(futures), total=len(futures), desc="Processing projects"):
                try:
                    cve_count = future.result()
                except Exception as e:
                    click.echo(f"  Future error: {e}")
        
        # First deduplicate identical CVEs
        unique_cves = self._deduplicate_cves(all_cves)
        
        # Then deduplicate by project (keep one CVE per project)
        project_unique_cves = self._deduplicate_cves_by_project(unique_cves)
        
        self.lookup_stats['total_cves_found'] = len(project_unique_cves)
        self.lookup_stats['lookup_time'] = time.time() - start_time
        
        # Save results
        self._save_project_cves(project_unique_cves)
        self._save_persistent_cache()  # Save cache for future runs
        self._print_lookup_summary()
        
        return project_unique_cves
    
    def find_cves_for_project(self, project: WasmProject) -> List[ProjectCVE]:
        """Find CVEs for a specific WASM project"""
        all_cves = []
        
        # Multiple lookup strategies
        
        # 1. OSV lookup by package name
        if project.ecosystem in ['crates.io', 'go_modules']:
            osv_cves = self._lookup_osv_by_package(project)
            all_cves.extend(osv_cves)
            self.lookup_stats['osv_lookups'] += 1
        
        # 2. GitHub Security Advisories
        github_cves = self._lookup_github_advisories(project)
        all_cves.extend(github_cves)
        self.lookup_stats['github_lookups'] += 1
        
        # 3. NVD lookup by project name
        nvd_cves = self._lookup_nvd_by_project(project)
        all_cves.extend(nvd_cves)
        self.lookup_stats['nvd_lookups'] += 1
        
        # 4. Repository-specific vulnerability searches
        repo_cves = self._search_repository_vulnerabilities(project)
        all_cves.extend(repo_cves)
        
        return all_cves
    
    def _lookup_osv_by_package(self, project: WasmProject) -> List[ProjectCVE]:
        """Query OSV database for specific package"""
        osv_cves = []
        
        try:
            # Cache key for this lookup
            cache_key = f"{project.ecosystem}:{project.name}"
            
            if cache_key in self.osv_cache:
                osv_data = self.osv_cache[cache_key]
            else:
                # Query OSV API directly for this package
                osv_query = {
                    "package": {
                        "name": project.name,
                        "ecosystem": self._map_ecosystem_to_osv(project.ecosystem)
                    }
                }
                
                response = requests.post(  # Changed from _rate_limited_request to direct requests.post
                    'https://api.osv.dev/v1/query',
                    json=osv_query,
                    headers={'Content-Type': 'application/json'},
                    timeout=30
                )
                
                if response.status_code == 200:
                    osv_data = response.json()
                    self.osv_cache[cache_key] = osv_data
                else:
                    osv_data = {}
            
            # Process OSV vulnerabilities
            vulns = osv_data.get('vulns', [])
            
            for vuln in vulns:
                cve = self._process_osv_vulnerability(vuln, project)
                if cve:
                    osv_cves.append(cve)
        
        except Exception as e:
            click.echo(f"    OSV lookup error for {project.name}: {e}")
        
        return osv_cves
    
    def _map_ecosystem_to_osv(self, ecosystem: str) -> str:
        """Map our ecosystem names to OSV ecosystem names"""
        mapping = {
            'crates.io': 'crates.io',
            'go_modules': 'Go',
            'npm': 'npm',
            'native': 'OSS-Fuzz'
        }
        return mapping.get(ecosystem, ecosystem)
    
    def _lookup_github_advisories(self, project: WasmProject) -> List[ProjectCVE]:
        """Lookup GitHub Security Advisories for project repository"""
        github_cves = []
        
        try:
            # Extract owner/repo from URL
            repo_info = self._parse_github_url(project.repo_url)
            if not repo_info:
                return github_cves
            
            owner, repo = repo_info
            cache_key = f"github:{owner}/{repo}"
            
            if cache_key in self.github_cache:
                advisories = self.github_cache[cache_key]
            else:
                # GitHub API for security advisories
                # GitHub API for security advisories
                advisories_url = f"https://api.github.com/repos/{owner}/{repo}/security-advisories"
                
                response = self._rate_limited_request(advisories_url, api_type='github', headers=self.github_headers)
                
                if response.status_code == 200:
                    advisories = response.json()
                    self.github_cache[cache_key] = advisories
                elif response.status_code == 404:
                    # Repository might not exist or have advisories
                    advisories = []
                    self.github_cache[cache_key] = advisories
                else:
                    advisories = []
            
            # Process GitHub advisories
            for advisory in advisories:
                cve = self._process_github_advisory(advisory, project)
                if cve:
                    github_cves.append(cve)
        
        except Exception as e:
            click.echo(f"    GitHub advisory lookup error for {project.name}: {e}")
        
        return github_cves
    
    def _lookup_nvd_by_project(self, project: WasmProject) -> List[ProjectCVE]:
        """Lookup NVD database by project name"""
        nvd_cves = []
        
        try:
            # Skip NVD for projects with generic names (saves time)
            if project.name.lower() in self.common_names:
                return nvd_cves
            
            # Use only the main project name to avoid redundant searches
            search_term = project.name
            cache_key = f"nvd:{search_term}"
            
            if cache_key in self.osv_cache:  # Reuse cache structure
                data = self.osv_cache[cache_key]
            else:
                nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={search_term}&resultsPerPage=20"
                
                response = self._rate_limited_request(nvd_url, api_type='nvd')
                
                if response.status_code == 200:
                    data = response.json()
                    self.osv_cache[cache_key] = data  # Cache the result
                else:
                    data = {}
            
            vulnerabilities = data.get('vulnerabilities', [])
            
            for vuln_data in vulnerabilities:
                cve = self._process_nvd_vulnerability(vuln_data, project)
                if cve:
                    nvd_cves.append(cve)
        
        except Exception as e:
            click.echo(f"    NVD lookup error for {project.name}: {e}")
        
        return nvd_cves
    
    def _search_repository_vulnerabilities(self, project: WasmProject) -> List[ProjectCVE]:
        """Search repository for vulnerability-related information"""
        repo_cves = []
        
        try:
            # Extract owner/repo from URL
            repo_info = self._parse_github_url(project.repo_url)
            if not repo_info:
                return repo_cves
            
            owner, repo = repo_info
            
            # Search for security-related issues
            issues_url = f"https://api.github.com/repos/{owner}/{repo}/issues?labels=security,vulnerability,CVE&state=all&per_page=50"
            
            response = self._rate_limited_request(issues_url, api_type='repo_search', headers=self.github_headers)
            
            if response.status_code == 200:
                issues = response.json()
                
                for issue in issues:
                    # Look for CVE mentions in issues
                    cve_matches = re.findall(r'CVE-\d{4}-\d{4,}', issue.get('title', '') + ' ' + issue.get('body', ''))
                    
                    for cve_id in cve_matches:
                        cve = ProjectCVE(
                            cve_id=cve_id,
                            advisory_id=f"github-issue-{issue['number']}",
                            source_project=project,
                            title=issue.get('title', ''),
                            description=issue.get('body', '')[:1000],  # Truncate
                            severity='unknown',
                            severity_score=0.0,
                            published_date=issue.get('created_at', ''),
                            affected_versions=[],
                            fixed_versions=[],
                            repository_url=project.repo_url,
                            vulnerable_commit=None,
                            fixed_commit=None,
                            cwe_ids=[],
                            references=[issue.get('html_url', '')],
                            wasm_compilation_confirmed=True,
                            metadata={
                                'source': 'github_issues',
                                'issue_number': issue['number'],
                                'issue_state': issue.get('state'),
                                'labels': [label.get('name', '') for label in issue.get('labels', [])]
                            }
                        )
                        repo_cves.append(cve)
        
        except Exception as e:
            click.echo(f"    Repository search error for {project.name}: {e}")
        
        return repo_cves
    
    def _parse_github_url(self, url: str) -> Optional[tuple]:
        """Parse GitHub URL to extract owner and repository name"""
        try:
            parsed = urlparse(url)
            if 'github.com' in parsed.netloc:
                path_parts = parsed.path.strip('/').split('/')
                if len(path_parts) >= 2:
                    return (path_parts[0], path_parts[1])
        except:
            pass
        return None
    
    def _process_osv_vulnerability(self, vuln: Dict, project: WasmProject) -> Optional[ProjectCVE]:
        """Process OSV vulnerability data into ProjectCVE"""
        try:
            # Extract CVE ID from aliases
            cve_id = None
            for alias in vuln.get('aliases', []):
                if alias.startswith('CVE-'):
                    cve_id = alias
                    break
            
            if not cve_id:
                cve_id = vuln.get('id', '')
            
            # Extract affected and fixed versions
            affected_versions = []
            fixed_versions = []
            
            for affected in vuln.get('affected', []):
                ranges = affected.get('ranges', [])
                for range_info in ranges:
                    events = range_info.get('events', [])
                    for event in events:
                        if 'introduced' in event:
                            affected_versions.append(event['introduced'])
                        elif 'fixed' in event:
                            fixed_versions.append(event['fixed'])
            
            # Extract severity
            severity_info = self._extract_severity_from_osv(vuln)
            
            # Extract CWE IDs
            cwe_ids = []
            db_specific = vuln.get('database_specific', {})
            if 'cwe_ids' in db_specific:
                cwe_ids = db_specific['cwe_ids']
            
            cve = ProjectCVE(
                cve_id=cve_id,
                advisory_id=vuln.get('id', ''),
                source_project=project,
                title=vuln.get('summary', ''),
                description=vuln.get('details', ''),
                severity=severity_info['level'],
                severity_score=severity_info['score'],
                published_date=vuln.get('published', ''),
                affected_versions=affected_versions,
                fixed_versions=fixed_versions,
                repository_url=project.repo_url,
                vulnerable_commit=None,
                fixed_commit=None,
                cwe_ids=cwe_ids,
                references=[ref.get('url', '') for ref in vuln.get('references', [])],
                wasm_compilation_confirmed=True,
                metadata={
                    'source': 'osv',
                    'osv_id': vuln.get('id'),
                    'withdrawn': vuln.get('withdrawn'),
                    'database_specific': db_specific,
                    'ecosystem_specific': vuln.get('ecosystem_specific', {})
                }
            )
            
            return cve
            
        except Exception as e:
            click.echo(f"    Error processing OSV vulnerability: {e}")
            return None
    
    def _process_github_advisory(self, advisory: Dict, project: WasmProject) -> Optional[ProjectCVE]:
        """Process GitHub security advisory into ProjectCVE"""
        try:
            # Extract CVE ID from identifiers
            cve_id = None
            for identifier in advisory.get('identifiers', []):
                if identifier.get('type') == 'CVE':
                    cve_id = identifier.get('value')
                    break
            
            if not cve_id:
                cve_id = advisory.get('ghsa_id', '')
            
            cve = ProjectCVE(
                cve_id=cve_id,
                advisory_id=advisory.get('ghsa_id', ''),
                source_project=project,
                title=advisory.get('summary', ''),
                description=advisory.get('description', ''),
                severity=advisory.get('severity', 'unknown').lower(),
                severity_score=advisory.get('cvss', {}).get('score', 0.0),
                published_date=advisory.get('published_at', ''),
                affected_versions=[],  # GitHub format is different, would need more parsing
                fixed_versions=[],
                repository_url=project.repo_url,
                vulnerable_commit=None,
                fixed_commit=None,
                cwe_ids=[cwe.get('cwe_id', '') for cwe in advisory.get('cwes', [])],
                references=[advisory.get('html_url', '')],
                wasm_compilation_confirmed=True,
                metadata={
                    'source': 'github_advisory',
                    'ghsa_id': advisory.get('ghsa_id'),
                    'state': advisory.get('state'),
                    'withdrawn_at': advisory.get('withdrawn_at')
                }
            )
            
            return cve
            
        except Exception as e:
            click.echo(f"    Error processing GitHub advisory: {e}")
            return None
    
    def _process_nvd_vulnerability(self, vuln_data: Dict, project: WasmProject) -> Optional[ProjectCVE]:
        """Process NVD vulnerability data into ProjectCVE"""
        try:
            cve_data = vuln_data.get('cve', {})
            cve_id = cve_data.get('id', '')
            
            # Check if this CVE is actually related to our project
            description = ''
            descriptions = cve_data.get('descriptions', [])
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Simple relevance check
            project_terms = [project.name.lower(), project.repo_url.lower()]
            if not any(term in description.lower() for term in project_terms):
                return None  # Not relevant to this project
            
            # Extract severity
            metrics = cve_data.get('metrics', {})
            severity_info = self._extract_severity_from_nvd(metrics)
            
            # Extract references
            references = []
            for ref in cve_data.get('references', []):
                references.append(ref.get('url', ''))
            
            cve = ProjectCVE(
                cve_id=cve_id,
                advisory_id=cve_id,
                source_project=project,
                title=f"NVD {cve_id}",
                description=description,
                severity=severity_info['level'],
                severity_score=severity_info['score'],
                published_date=cve_data.get('published', ''),
                affected_versions=[],
                fixed_versions=[],
                repository_url=project.repo_url,
                vulnerable_commit=None,
                fixed_commit=None,
                cwe_ids=[weakness.get('description', [{}])[0].get('value', '') for weakness in cve_data.get('weaknesses', [])],
                references=references,
                wasm_compilation_confirmed=True,
                metadata={
                    'source': 'nvd',
                    'nvd_id': cve_id,
                    'source_identifier': cve_data.get('sourceIdentifier'),
                    'vuln_status': cve_data.get('vulnStatus')
                }
            )
            
            return cve
            
        except Exception as e:
            click.echo(f"    Error processing NVD vulnerability: {e}")
            return None
    
    def _extract_severity_from_osv(self, vuln: Dict) -> Dict[str, Any]:
        """Extract severity information from OSV vulnerability"""
        severity_info = {'level': 'medium', 'score': 5.0}
        
        # Check database_specific for severity
        db_specific = vuln.get('database_specific', {})
        if 'severity' in db_specific:
            severity_info['level'] = db_specific['severity'].lower()
        
        # Check for CVSS score
        if 'cvss' in db_specific:
            cvss = db_specific['cvss']
            if isinstance(cvss, dict) and 'baseScore' in cvss:
                score = float(cvss['baseScore'])
                severity_info['score'] = score
                
                if score >= 9.0:
                    severity_info['level'] = 'critical'
                elif score >= 7.0:
                    severity_info['level'] = 'high'
                elif score >= 4.0:
                    severity_info['level'] = 'medium'
                else:
                    severity_info['level'] = 'low'
        
        return severity_info
    
    def _extract_severity_from_nvd(self, metrics: Dict) -> Dict[str, Any]:
        """Extract severity information from NVD metrics"""
        severity_info = {'level': 'medium', 'score': 5.0}
        
        # Check CVSS v3.1 first, then v3.0, then v2.0
        for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            if version in metrics:
                metric_list = metrics[version]
                if metric_list:
                    cvss_data = metric_list[0].get('cvssData', {})
                    score = cvss_data.get('baseScore', 5.0)
                    severity_info['score'] = score
                    
                    if score >= 9.0:
                        severity_info['level'] = 'critical'
                    elif score >= 7.0:
                        severity_info['level'] = 'high'
                    elif score >= 4.0:
                        severity_info['level'] = 'medium'
                    else:
                        severity_info['level'] = 'low'
                    break
        
        return severity_info
    
    def _deduplicate_cves(self, cves: List[ProjectCVE]) -> List[ProjectCVE]:
        """Remove duplicate CVEs based on CVE ID and project"""
        seen = set()
        unique_cves = []
        
        for cve in cves:
            # Create unique key from CVE ID and project
            key = f"{cve.cve_id}:{cve.source_project.repo_url}"
            
            if key not in seen:
                seen.add(key)
                unique_cves.append(cve)
        
        return unique_cves
    
    def _save_project_cves(self, cves: List[ProjectCVE]):
        """Save discovered CVEs to JSON file"""
        output_file = self.output_dir / "project_cves.json"
        
        data = {
            "lookup_timestamp": time.time(),
            "lookup_stats": self.lookup_stats,
            "total_cves": len(cves),
            "cves": [cve.to_dict() for cve in cves]
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        click.echo(f"Saved {len(cves)} CVEs to {output_file}")
    
    def _print_lookup_summary(self):
        """Print summary of CVE lookup results"""
        stats = self.lookup_stats
        
        click.echo("\nCVE Lookup Summary:")
        click.echo("=" * 40)
        click.echo(f"Projects processed: {stats['projects_processed']}")
        click.echo(f"Total CVEs found: {stats['total_cves_found']}")
        click.echo(f"OSV lookups: {stats['osv_lookups']}")
        click.echo(f"GitHub lookups: {stats['github_lookups']}")
        click.echo(f"NVD lookups: {stats['nvd_lookups']}")
        click.echo(f"API calls made: {stats['api_calls_made']}")
        click.echo(f"Lookup time: {stats['lookup_time']:.2f}s")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Lookup CVEs for WASM projects')
    parser.add_argument('--projects-file', required=True, help='JSON file with discovered WASM projects')
    parser.add_argument('--output', default='data/project_cves', help='Output directory')
    
    args = parser.parse_args()
    
    # Load projects
    with open(args.projects_file, 'r') as f:
        projects_data = json.load(f)
    
    projects = [WasmProject(**proj) for proj in projects_data['projects']]
    
    # Lookup CVEs
    lookup = ProjectCVELookup(output_dir=args.output)
    cves = lookup.find_cves_for_projects(projects)
    
    click.echo(f"CVE lookup complete: {len(cves)} CVEs found for WASM projects")
