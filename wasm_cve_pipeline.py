#!/usr/bin/env python3
"""
FILENAME: wasm_cve_pipeline.py
DESCRIPTION: Complete pipeline for WASM project discovery -> CVE lookup -> compilation
"""

import json
import time
import sys
from pathlib import Path
from typing import List, Dict, Any
import click
from dataclasses import asdict
from tqdm import tqdm

# Add current directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# Add paths for imports
from discovery.wasm_project_discovery import WasmProjectDiscovery, WasmProject
from lookup.project_cve_lookup import ProjectCVELookup, ProjectCVE
from compilation.wasm_compiler import WasmCompiler, BatchCompiler, CompilationResult, CompilationStatus

class WasmCVEPipeline:
    """Complete pipeline for WASM CVE dataset generation"""
    
    def __init__(self, output_base_dir: str = "data"):
        self.output_base_dir = Path(output_base_dir)
        self.output_base_dir.mkdir(parents=True, exist_ok=True)
        
        # Component output directories
        self.projects_dir = self.output_base_dir / "wasm_projects"
        self.cves_dir = self.output_base_dir / "project_cves"
        self.compiled_dir = self.output_base_dir / "compiled_wasm"
        
        # Initialize components
        self.discovery = WasmProjectDiscovery(self.projects_dir)
        self.cve_lookup = ProjectCVELookup(output_dir=self.cves_dir)
        self.compiler = WasmCompiler(self.compiled_dir)
        self.batch_compiler = BatchCompiler(self.compiler)
        
        # Pipeline statistics
        self.pipeline_stats = {
            'start_time': 0,
            'discovery_time': 0,
            'cve_lookup_time': 0,
            'compilation_time': 0,
            'total_time': 0,
            'projects_discovered': 0,
            'cves_found': 0,
            'successful_compilations': 0,
            'final_dataset_size': 0
        }
    
    def run_complete_pipeline(self, 
                             max_projects: int = None,
                             min_confidence: float = 0.7,
                             compile_vulnerable_versions: bool = True) -> Dict[str, Any]:
        """Run the complete WASM CVE pipeline"""
        
        click.echo("Starting complete WASM CVE dataset generation pipeline...")
        self.pipeline_stats['start_time'] = time.time()
        
        # Step 1: Discover WASM-capable projects
        click.echo("\n" + "="*60)
        click.echo("STEP 1: Discovering WASM-capable projects")
        click.echo("="*60)
        
        discovery_start = time.time()
        wasm_projects = self.discovery.discover_all_wasm_projects()
        
        # Filter by confidence score
        high_confidence_projects = [
            p for p in wasm_projects 
            if p.confidence_score >= min_confidence
        ]
        
        if max_projects:
            high_confidence_projects = high_confidence_projects[:max_projects]
        
        self.pipeline_stats['discovery_time'] = time.time() - discovery_start
        self.pipeline_stats['projects_discovered'] = len(high_confidence_projects)
        
        click.echo(f"Discovered {len(wasm_projects)} total projects")
        click.echo(f"Filtered to {len(high_confidence_projects)} high-confidence projects")
        
        if not high_confidence_projects:
            click.echo("No high-confidence WASM projects found. Exiting.")
            return self.pipeline_stats
        
        # Step 2: Lookup CVEs for discovered projects
        click.echo("\n" + "="*60)
        click.echo("STEP 2: Looking up CVEs for WASM projects")
        click.echo("="*60)
        
        cve_lookup_start = time.time()
        project_cves = self.cve_lookup.find_cves_for_projects(high_confidence_projects)
        
        self.pipeline_stats['cve_lookup_time'] = time.time() - cve_lookup_start
        self.pipeline_stats['cves_found'] = len(project_cves)
        
        click.echo(f"Found {len(project_cves)} CVEs across WASM projects")
        
        if not project_cves:
            click.echo("No CVEs found for WASM projects.")
            
            # Generate final report for early exit
            self.pipeline_stats['total_time'] = time.time() - self.pipeline_stats['start_time']
            self.pipeline_stats['cves_found'] = 0
            self.pipeline_stats['successful_compilations'] = 0
            self.pipeline_stats['final_dataset_size'] = 0
            
            final_report = {
                'pipeline_stats': self.pipeline_stats,
                'cve_analysis': {'total_cves': 0, 'by_language': {}, 'by_severity': {}},
                'compilation_analysis': {'total_attempts': 0, 'by_language': {}, 'by_status': {}, 'success_rate': 0}
            }
            
            self._save_complete_dataset(high_confidence_projects, [], [])
            self._print_pipeline_summary()
            
            return final_report
        
        # Step 3: Compile vulnerable versions to WASM
        if compile_vulnerable_versions:
            click.echo("\n" + "="*60)
            click.echo("STEP 3: Compiling vulnerable versions to WASM")
            click.echo("="*60)
            
            compilation_start = time.time()
            compilation_results = self._compile_vulnerable_versions(project_cves)
            
            self.pipeline_stats['compilation_time'] = time.time() - compilation_start
            
            successful_compilations = [
                r for r in compilation_results 
                if r.status.value == 'success'
            ]
            
            self.pipeline_stats['successful_compilations'] = len(successful_compilations)
            self.pipeline_stats['final_dataset_size'] = len(successful_compilations)
            
            click.echo(f"Successfully compiled {len(successful_compilations)} vulnerable WASM binaries")
        
        # Generate final report
        self.pipeline_stats['total_time'] = time.time() - self.pipeline_stats['start_time']
        final_report = self._generate_pipeline_report(project_cves, compilation_results if compile_vulnerable_versions else [])
        
        # Save complete dataset
        self._save_complete_dataset(high_confidence_projects, project_cves, 
                                   compilation_results if compile_vulnerable_versions else [])
        
        self._print_pipeline_summary()
        
        return final_report
    
    def _deduplicate_compilation_targets(self, cves: List[ProjectCVE]) -> List[Dict]:
        """Deduplicate compilation targets by repository to avoid multiple clones"""
        seen_repos = {}
        unique_targets = []
        
        for cve in cves:
            repo_url = cve.source_project.repo_url
            
            if repo_url not in seen_repos:
                # First CVE for this repository
                seen_repos[repo_url] = cve
                
                vulnerability_data = {
                    'id': cve.cve_id,
                    'language': cve.source_project.language,
                    'vulnerability_type': self._infer_vulnerability_type(cve),
                    'severity': cve.severity,
                    'published_date': cve.published_date
                }
                
                project_config = {
                    'source_directory': self._get_project_source_directory(cve),
                    'vulnerable_commit': cve.vulnerable_commit,
                    'compilation_config': self._get_compilation_config(cve.source_project),
                    'release': True,
                    'optimize': True
                }
                
                unique_targets.append({
                    'project_id': f"{cve.source_project.name}_{cve.cve_id}",
                    'vulnerability_data': vulnerability_data,
                    'project_config': project_config,
                    'source_cve': cve,
                    'all_cves': [cve]  # Track all CVEs for this repo
                })
            else:
                # Additional CVE for same repository - just track it
                for target in unique_targets:
                    if target['source_cve'].source_project.repo_url == repo_url:
                        target['all_cves'].append(cve)
                        break
        
        click.echo(f"Deduplicated {len(cves)} CVEs into {len(unique_targets)} unique repositories")
        return unique_targets
    
    def _compile_vulnerable_versions(self, cves: List[ProjectCVE]) -> List[CompilationResult]:
        """Compile vulnerable versions of projects to WASM"""
        
        # Deduplicate by repository first
        compilation_targets = self._deduplicate_compilation_targets(cves)
        
        click.echo(f"Starting compilation of {len(compilation_targets)} unique repositories")
        
        # Compile all targets
        results = []
        
        for target in tqdm(compilation_targets, desc="Compiling vulnerable versions"):
            try:
                click.echo(f"Compiling project: {target['project_id']}")
                click.echo(f"Source directory: {target['project_config']['source_directory']}")
                click.echo(f"Language: {target['vulnerability_data']['language']}")
                
                # Check if source directory exists
                source_dir = Path(target['project_config']['source_directory'])
                if not source_dir.exists():
                    click.echo(f"ERROR: Source directory does not exist: {source_dir}")
                    continue
                
                result = self.compiler.compile_project(
                    target['project_id'],
                    target['vulnerability_data'],
                    target['project_config']
                )
                
                click.echo(f"Compilation result: {result.status}")
                if result.error_message:
                    click.echo(f"Error: {result.error_message}")
                
                # Add source CVE information to result
                result.source_cve = target['source_cve']
                results.append(result)
                
            except Exception as e:
                click.echo(f"Compilation exception for {target['project_id']}: {e}")
                import traceback
                traceback.print_exc()
        
        # Save results for debugging
        results_file = self.compiled_dir / "compilation_results.json"
        with open(results_file, 'w') as f:
            json.dump([result.to_dict() for result in results], f, indent=2, default=str)
        
        click.echo(f"Saved {len(results)} compilation results to {results_file}")
        
        return results
    
    def _get_project_source_directory(self, cve: ProjectCVE) -> Path:
        """Get source directory for project (clone if necessary)"""
        # For now, assume we need to clone the repository
        repo_name = cve.source_project.name
        clone_dir = self.output_base_dir / "repositories" / repo_name
        
        if not clone_dir.exists():
            # Clone the repository
            import subprocess
            try:
                subprocess.run([
                    'git', 'clone', '--depth', '1', 
                    cve.source_project.repo_url, 
                    str(clone_dir)
                ], check=True, capture_output=True)
            except subprocess.CalledProcessError:
                # If shallow clone fails, try full clone
                try:
                    subprocess.run([
                        'git', 'clone', cve.source_project.repo_url, str(clone_dir)
                    ], check=True, capture_output=True)
                except subprocess.CalledProcessError as e:
                    click.echo(f"Failed to clone {cve.source_project.repo_url}: {e}")
                    return Path("/nonexistent")  # Will cause compilation to fail gracefully
        
        return clone_dir
    
    def _get_compilation_config(self, project: WasmProject) -> Dict[str, Any]:
        """Get compilation configuration based on project characteristics"""
        config = {}
        
        if project.language == 'rust':
            config['rustflags'] = '--cfg=web_sys_unstable_apis'
            if project.metadata.get('wasm_dependency'):
                config['features'] = ['web-sys', 'js-sys']
        
        elif project.language == 'go':
            config['build_flags'] = ['-tags', 'js,wasm']
        
        elif project.language in ['c', 'c++']:
            config['emcc_flags'] = ['-O2', '-s', 'WASM=1']
        
        return config
    
    def _infer_vulnerability_type(self, cve: ProjectCVE) -> str:
        """Infer vulnerability type from CVE data"""
        description = (cve.title + ' ' + cve.description).lower()
        
        if any(term in description for term in ['buffer overflow', 'memory', 'heap', 'stack']):
            return 'memory_safety'
        elif any(term in description for term in ['injection', 'validation', 'input']):
            return 'input_validation'
        elif any(term in description for term in ['dos', 'denial', 'crash']):
            return 'denial_of_service'
        elif any(term in description for term in ['crypto', 'certificate', 'encryption']):
            return 'cryptographic'
        else:
            return 'other'
    
    def _generate_pipeline_report(self, cves: List[ProjectCVE], compilation_results: List[CompilationResult]) -> Dict[str, Any]:
        """Generate comprehensive pipeline report"""
        
        # CVE analysis
        cve_by_language = {}
        cve_by_severity = {}
        
        for cve in cves:
            lang = cve.source_project.language
            cve_by_language[lang] = cve_by_language.get(lang, 0) + 1
            
            severity = cve.severity
            cve_by_severity[severity] = cve_by_severity.get(severity, 0) + 1
        
        # Compilation analysis
        compilation_by_language = {}
        compilation_by_status = {}
        
        for result in compilation_results:
            lang = result.language
            if lang not in compilation_by_language:
                compilation_by_language[lang] = {'total': 0, 'success': 0}
            compilation_by_language[lang]['total'] += 1
            if result.status.value == 'success':
                compilation_by_language[lang]['success'] += 1
            
            status = result.status.value
            compilation_by_status[status] = compilation_by_status.get(status, 0) + 1
        
        return {
            'pipeline_stats': self.pipeline_stats,
            'cve_analysis': {
                'total_cves': len(cves),
                'by_language': cve_by_language,
                'by_severity': cve_by_severity
            },
            'compilation_analysis': {
                'total_attempts': len(compilation_results),
                'by_language': compilation_by_language,
                'by_status': compilation_by_status,
                'success_rate': (compilation_by_status.get('success', 0) / len(compilation_results)) if compilation_results else 0
            }
        }
    
    def _save_complete_dataset(self, projects: List[WasmProject], cves: List[ProjectCVE], results: List[CompilationResult]):
        """Save the complete dataset with all components"""
        
        dataset = {
            'generation_timestamp': time.time(),
            'pipeline_version': '1.0',
            'pipeline_stats': self.pipeline_stats,
            'discovered_projects': [p.to_dict() for p in projects],
            'project_cves': [cve.to_dict() for cve in cves],
            'compilation_results': [asdict(r) for r in results],
            'successful_wasm_binaries': [
                {
                    'cve_id': r.vulnerability_id,
                    'project_name': r.project_id,
                    'wasm_path': str(r.wasm_path) if r.wasm_path else None,
                    'wasm_size': r.wasm_size,
                    'compilation_time': r.compilation_time,
                    'language': r.language
                }
                for r in results if r.status.value == 'success'
            ]
        }
        
        output_file = self.output_base_dir / "wasm_cve_complete_dataset.json"
        with open(output_file, 'w') as f:
            json.dump(dataset, f, indent=2, default=str)
        
        click.echo(f"Complete dataset saved to {output_file}")
    
    def _print_pipeline_summary(self):
        """Print comprehensive pipeline summary"""
        stats = self.pipeline_stats
        
        click.echo("\n" + "="*60)
        click.echo("PIPELINE EXECUTION SUMMARY")
        click.echo("="*60)
        
        click.echo(f"Total execution time: {stats['total_time']:.2f} seconds")
        click.echo(f"  - Discovery: {stats['discovery_time']:.2f}s")
        click.echo(f"  - CVE lookup: {stats['cve_lookup_time']:.2f}s")
        click.echo(f"  - Compilation: {stats['compilation_time']:.2f}s")
        
        click.echo(f"\nResults:")
        click.echo(f"  - WASM projects discovered: {stats['projects_discovered']}")
        click.echo(f"  - CVEs found: {stats['cves_found']}")
        click.echo(f"  - Successful WASM compilations: {stats['successful_compilations']}")
        click.echo(f"  - Final dataset size: {stats['final_dataset_size']} WASM binaries")
        
        if stats['cves_found'] > 0:
            success_rate = (stats['successful_compilations'] / stats['cves_found']) * 100
            click.echo(f"  - Compilation success rate: {success_rate:.1f}%")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Complete WASM CVE dataset generation pipeline')
    parser.add_argument('--max-projects', type=int, help='Maximum number of projects to process')
    parser.add_argument('--min-confidence', type=float, default=0.7, help='Minimum confidence score for projects')
    parser.add_argument('--discovery-only', action='store_true', help='Only run project discovery')
    parser.add_argument('--lookup-only', action='store_true', help='Only run CVE lookup (requires existing projects)')
    parser.add_argument('--compile-only', action='store_true', help='Only run compilation (requires existing CVEs)')
    parser.add_argument('--output-dir', default='data', help='Base output directory')
    
    args = parser.parse_args()
    
    pipeline = WasmCVEPipeline(args.output_dir)
    
    if args.discovery_only:
        click.echo("Running discovery only...")
        projects = pipeline.discovery.discover_all_wasm_projects()
        click.echo(f"Discovery complete: {len(projects)} projects found")
        
    elif args.lookup_only:
        click.echo("Running CVE lookup only...")
        # Load existing projects
        projects_file = pipeline.projects_dir / "discovered_wasm_projects.json"
        if not projects_file.exists():
            click.echo("No existing projects found. Run discovery first.")
            sys.exit(1)
        
        with open(projects_file, 'r') as f:
            projects_data = json.load(f)
        
        projects = [WasmProject(**proj) for proj in projects_data['projects']]
        cves = pipeline.cve_lookup.find_cves_for_projects(projects)
        click.echo(f"CVE lookup complete: {len(cves)} CVEs found")
        
    elif args.compile_only:
        click.echo("Running compilation only...")
        # Load existing CVEs
        cves_file = pipeline.cves_dir / "project_cves.json"
        if not cves_file.exists():
            click.echo("No existing CVEs found. Run discovery and lookup first.")
            sys.exit(1)
        
        with open(cves_file, 'r') as f:
            cves_data = json.load(f)
        
        cves = [ProjectCVE(**cve_dict) for cve_dict in cves_data['cves']]
        results = pipeline._compile_vulnerable_versions(cves)
        
        successful = len([r for r in results if r.status.value == 'success'])
        click.echo(f"Compilation complete: {successful}/{len(results)} successful")
        
    else:
        # Run complete pipeline
        final_report = pipeline.run_complete_pipeline(
            max_projects=args.max_projects,
            min_confidence=args.min_confidence,
            compile_vulnerable_versions=True
        )
        
        click.echo(f"\nPipeline complete! Final dataset: {final_report['pipeline_stats']['final_dataset_size']} WASM binaries")
