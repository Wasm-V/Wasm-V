#!/usr/bin/env python3
"""
WASM-V: WebAssembly Vulnerability Dataset Generator

A security research pipeline that discovers WebAssembly-capable projects,
identifies associated CVEs, and compiles vulnerable versions to WASM binaries
for security analysis and research.

Usage:
    python run_pipeline.py                    # Generate dataset with 10 projects
    python run_pipeline.py --max-projects 50  # Process more projects
    python run_pipeline.py --no-compile       # Discovery and CVE lookup only
"""

import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from wasm_cve_pipeline import WasmCVEPipeline
import click

@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.option('--max-projects', '-n', default=10, show_default=True,
              help='Maximum number of projects to discover and process')
@click.option('--min-confidence', '-c', default=0.7, show_default=True, 
              type=click.FloatRange(0.0, 1.0),
              help='Minimum confidence score for WASM project filtering (0.0-1.0)')
@click.option('--compile/--no-compile', default=True, show_default=True,
              help='Compile vulnerable versions to WASM binaries')
@click.option('--output-dir', '-o', default='data', show_default=True,
              help='Output directory for generated dataset')
@click.option('--discovery-only', is_flag=True, 
              help='Run project discovery stage only (skip CVE lookup and compilation)')
@click.option('--lookup-only', is_flag=True,
              help='Run discovery and CVE lookup only (skip compilation)')
@click.option('--languages', '-l', multiple=True, 
              type=click.Choice(['rust', 'go', 'cpp', 'c'], case_sensitive=False),
              help='Filter projects by programming language (can specify multiple)')
@click.option('--severity', '-s', multiple=True,
              type=click.Choice(['critical', 'high', 'medium', 'low'], case_sensitive=False),
              help='Filter CVEs by severity level (can specify multiple)')
@click.option('--verbose', '-v', is_flag=True, 
              help='Enable verbose output for debugging')
@click.option('--dry-run', is_flag=True,
              help='Show what would be processed without executing')
@click.option('--test-vulnerabilities', is_flag=True,
              help='Execute vulnerability testing after compilation')
@click.option('--setup-execution', is_flag=True,
              help='Setup WASM execution tools (wasmtime, wasm-tools)')
def run_pipeline(max_projects, min_confidence, compile, output_dir, 
                discovery_only, lookup_only, languages, severity, verbose, dry_run,
                test_vulnerabilities, setup_execution):
    """
    Generate a curated WebAssembly vulnerability dataset for security research.
    
    This pipeline discovers projects that can compile to WebAssembly, identifies
    associated CVEs, and optionally compiles vulnerable versions to WASM binaries.
    The resulting dataset enables security researchers to analyze WebAssembly
    vulnerabilities in a controlled environment.
    
    \b
    Pipeline Stages:
      1. Discovery  - Find WASM-capable projects via crates.io, GitHub API
      2. CVE Lookup - Search OSV.dev and GitHub Security Advisories  
      3. Compilation- Compile vulnerable versions to WASM binaries
    
    \b
    Output Structure:
      data/wasm_projects/           - Discovered projects metadata
      data/project_cves/           - CVE information and mappings
      data/compiled_wasm/          - Compiled WASM binaries
      data/repositories/           - Cloned source repositories
      data/wasm_cve_complete_dataset.json - Final curated dataset
    
    \b
    Examples:
      # Generate small research dataset (10 projects)
      python run_pipeline.py
      
      # Large dataset with high-confidence projects only  
      python run_pipeline.py -n 100 -c 0.8
      
      # Discovery phase only for exploration
      python run_pipeline.py --discovery-only -n 50
      
      # Focus on Rust projects with critical vulnerabilities
      python run_pipeline.py -l rust -s critical -n 25
    """
    
    # Handle setup mode
    if setup_execution:
        click.echo("Setting up WASM execution tools...")
        try:
            import sys
            from pathlib import Path
            sys.path.insert(0, str(Path(__file__).parent))
            from execution.setup_execution_tools import main as setup_main
            setup_main()
        except ImportError as e:
            click.echo(f"Error: execution module not found: {e}", err=True)
        return
    
    # Handle mutually exclusive options
    if discovery_only and lookup_only:
        click.echo("Error: --discovery-only and --lookup-only cannot be used together", err=True)
        sys.exit(1)
    
    if discovery_only:
        compile = False
        lookup_only = False
    elif lookup_only:
        compile = False
    
    # Print banner and configuration
    click.echo("=" * 70)
    click.echo("WASM-V: WebAssembly Vulnerability Dataset Generator")
    click.echo("=" * 70)
    click.echo("Goal: Generate curated WASM vulnerability dataset for security research")
    click.echo()
    
    if dry_run:
        click.echo("DRY RUN MODE - No actual processing will occur")
        click.echo()
    
    # Configuration summary
    click.echo("Configuration:")
    click.echo(f"   • Max projects: {max_projects}")
    click.echo(f"   • Min confidence: {min_confidence}")
    click.echo(f"   • Output directory: {output_dir}")
    
    if languages:
        click.echo(f"   • Language filter: {', '.join(languages)}")
    if severity:
        click.echo(f"   • Severity filter: {', '.join(severity)}")
    
    # Pipeline stages
    click.echo()
    click.echo("Pipeline stages:")
    if discovery_only:
        click.echo("   [ENABLED]  Discovery (projects)")
        click.echo("   [SKIPPED]  CVE Lookup (skipped)")
        click.echo("   [SKIPPED]  Compilation (skipped)")
    elif lookup_only:
        click.echo("   [ENABLED]  Discovery (projects)")
        click.echo("   [ENABLED]  CVE Lookup (vulnerabilities)")
        click.echo("   [SKIPPED]  Compilation (skipped)")
    else:
        click.echo("   [ENABLED]  Discovery (projects)")
        click.echo("   [ENABLED]  CVE Lookup (vulnerabilities)")
        click.echo("   [ENABLED]  Compilation (WASM binaries)" if compile else "   [DISABLED] Compilation (disabled)")
        if test_vulnerabilities and compile:
            click.echo("   [ENABLED]  Vulnerability Testing (execution traces)")
    
    if dry_run:
        click.echo()
        click.echo("Dry run complete. Use without --dry-run to execute.")
        return
    
    click.echo()
    click.echo("Starting pipeline execution...")
    
    # Initialize pipeline
    pipeline = WasmCVEPipeline(output_base_dir=output_dir)
    
    # Run complete pipeline
    try:
        results = pipeline.run_complete_pipeline(
            max_projects=max_projects,
            min_confidence=min_confidence,
            compile_vulnerable_versions=compile
        )
        
        # Print detailed summary
        click.echo()
        click.echo("=" * 70)
        click.echo("DATASET GENERATION COMPLETED SUCCESSFULLY")
        click.echo("=" * 70)
        
        stats = results['pipeline_stats']
        click.echo("Pipeline Statistics:")
        click.echo(f"   • Projects discovered: {stats['projects_discovered']}")
        click.echo(f"   • CVEs identified: {stats['cves_found']}")
        click.echo(f"   • Successful compilations: {stats['successful_compilations']}")
        click.echo(f"   • Total execution time: {stats['total_time']:.1f}s")
        
        # Dataset ready message
        click.echo()
        if stats['successful_compilations'] > 0:
            click.echo(f"Security Research Dataset Ready!")
            click.echo(f"   {stats['successful_compilations']} WASM binaries compiled")
            click.echo(f"   Complete dataset: {output_dir}/wasm_cve_complete_dataset.json")
            click.echo()
            click.echo("Ready for security analysis:")
            click.echo(f"   • Binary analysis: {output_dir}/compiled_wasm/*.wasm")
            click.echo(f"   • Vulnerability data: {output_dir}/project_cves/")
            click.echo(f"   • Source repositories: {output_dir}/repositories/")
            
            # Run vulnerability testing if requested
            if test_vulnerabilities:
                click.echo()
                click.echo("Running vulnerability testing...")
                try:
                    from execution.vulnerability_tester import VulnerabilityTester
                    from lookup.project_cve_lookup import ProjectCVE
                    from pathlib import Path
                    import json
                    
                    # Load CVE data
                    cves_file = Path(output_dir) / "project_cves" / "project_cves.json"
                    if cves_file.exists():
                        with open(cves_file) as f:
                            cves_data = json.load(f)
                        
                        # Convert to ProjectCVE objects
                        cves = []
                        # Handle both list format and dict with 'cves' key
                        if isinstance(cves_data, dict) and 'cves' in cves_data:
                            cve_list = cves_data['cves']
                        elif isinstance(cves_data, list):
                            cve_list = cves_data
                        else:
                            cve_list = []
                        
                        if cve_list:
                            # Simple conversion - create minimal ProjectCVE objects for testing
                            from discovery.wasm_project_discovery import WasmProject
                            for cve_data in cve_list:
                                try:
                                    # Create minimal objects for testing
                                    wasm_project = WasmProject(
                                        name=cve_data.get('source_project', {}).get('name', 'unknown'),
                                        ecosystem=cve_data.get('source_project', {}).get('ecosystem', 'unknown'),
                                        repo_url=cve_data.get('repository_url', ''),
                                        language=cve_data.get('source_project', {}).get('language', 'rust'),
                                        wasm_confirmed=True,
                                        confidence_score=0.8,
                                        discovery_method='loaded',
                                        metadata={}
                                    )
                                    
                                    cve = ProjectCVE(
                                        cve_id=cve_data.get('cve_id', 'UNKNOWN'),
                                        advisory_id=cve_data.get('advisory_id', ''),
                                        source_project=wasm_project,
                                        title=cve_data.get('title', ''),
                                        description=cve_data.get('description', ''),
                                        severity=cve_data.get('severity', 'medium'),
                                        severity_score=cve_data.get('severity_score', 5.0),
                                        published_date=cve_data.get('published_date', ''),
                                        affected_versions=cve_data.get('affected_versions', []),
                                        fixed_versions=cve_data.get('fixed_versions', []),
                                        repository_url=cve_data.get('repository_url', ''),
                                        vulnerable_commit=cve_data.get('vulnerable_commit'),
                                        fixed_commit=cve_data.get('fixed_commit'),
                                        cwe_ids=cve_data.get('cwe_ids', []),
                                        references=cve_data.get('references', []),
                                        wasm_compilation_confirmed=True,
                                        metadata=cve_data.get('metadata', {})
                                    )
                                    cves.append(cve)
                                except Exception as e:
                                    if verbose:
                                        click.echo(f"   • Failed to load CVE: {e}")
                        
                        click.echo(f"   • Loaded {len(cves)} CVEs for testing")
                        
                        tester = VulnerabilityTester(
                            Path(output_dir) / "compiled_wasm",
                            Path(output_dir) / "vulnerability_tests"
                        )
                        
                        if cves:
                            test_results = tester.test_all_vulnerabilities(cves)
                            
                            confirmed_vulns = sum(1 for t in test_results if t.vulnerability_confirmed)
                            successful_executions = sum(1 for t in test_results if t.vulnerable_trace is not None)
                            
                            click.echo(f"   • Vulnerability tests: {len(test_results)} total")
                            click.echo(f"   • Successful executions: {successful_executions}")
                            click.echo(f"   • Confirmed vulnerabilities: {confirmed_vulns}")
                            click.echo(f"   • Test results: {output_dir}/vulnerability_tests/")
                        else:
                            click.echo("   • No valid CVE data loaded for testing")
                    else:
                        click.echo("   • No CVE data found for vulnerability testing")
                        
                except ImportError:
                    click.echo("   • Vulnerability testing tools not installed")
                    click.echo("   • Run with --setup-execution to install tools")
                except Exception as e:
                    if verbose:
                        import traceback
                        traceback.print_exc()
                    else:
                        click.echo(f"   • Vulnerability testing failed: {e}")
        elif stats['cves_found'] > 0:
            click.echo(f"CVE Research Dataset Ready!")
            click.echo(f"   {stats['cves_found']} vulnerabilities catalogued")
            click.echo(f"   CVE data: {output_dir}/project_cves/project_cves.json")
        else:
            click.echo("WARNING: Limited dataset generated:")
            click.echo(f"   {stats['projects_discovered']} projects discovered")
            click.echo("   TIP: Try lowering --min-confidence or increasing --max-projects")
            
    except KeyboardInterrupt:
        click.echo("\nPipeline interrupted by user")
        sys.exit(0)
    except Exception as e:
        click.echo(f"\nPipeline failed: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        else:
            click.echo("   TIP: Use --verbose for detailed error information")
        sys.exit(1)

if __name__ == "__main__":
    run_pipeline()