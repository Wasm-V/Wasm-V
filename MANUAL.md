# WASM-V(1) Manual Page

## NAME
wasm-v - WebAssembly Vulnerability Dataset Generator

## SYNOPSIS
```
python run_pipeline.py [OPTIONS]
```

## DESCRIPTION
WASM-V is a security research pipeline that generates curated WebAssembly vulnerability datasets. It discovers projects capable of compiling to WebAssembly, identifies associated CVEs, and optionally compiles vulnerable versions to WASM binaries for controlled security analysis.

The pipeline operates in three stages:
1. **Discovery**: Searches crates.io, GitHub API, and other sources for WASM-capable projects
2. **CVE Lookup**: Queries OSV.dev and GitHub Security Advisories for vulnerabilities  
3. **Compilation**: Compiles vulnerable versions to WASM binaries using appropriate toolchains

## OPTIONS

### General Options
- **-n, --max-projects INTEGER**  
  Maximum number of projects to discover and process (default: 10)

- **-c, --min-confidence FLOAT**  
  Minimum confidence score for WASM project filtering, range 0.0-1.0 (default: 0.7)

- **-o, --output-dir TEXT**  
  Output directory for generated dataset (default: data)

- **-v, --verbose**  
  Enable verbose output for debugging

- **--dry-run**  
  Show what would be processed without executing

- **-h, --help**  
  Show help message and exit

### Pipeline Control
- **--discovery-only**  
  Run project discovery stage only (skip CVE lookup and compilation)

- **--lookup-only**  
  Run discovery and CVE lookup only (skip compilation)

- **--compile / --no-compile**  
  Whether to compile vulnerable versions to WASM binaries (default: compile)

### Filtering Options
- **-l, --languages [rust|go|cpp|c]**  
  Filter projects by programming language (can specify multiple)

- **-s, --severity [critical|high|medium|low]**  
  Filter CVEs by severity level (can specify multiple)

## EXAMPLES

### Basic Usage
```bash
# Generate small research dataset with defaults
python run_pipeline.py

# Generate larger dataset with high-confidence projects
python run_pipeline.py -n 100 -c 0.8
```

### Targeted Research
```bash
# Focus on Rust projects with critical vulnerabilities
python run_pipeline.py -l rust -s critical -n 25

# Multi-language security research
python run_pipeline.py -l rust -l go -l cpp -s critical -s high -n 50
```

### Exploration Workflows
```bash
# Discovery phase only for project exploration
python run_pipeline.py --discovery-only -n 50

# CVE research without compilation overhead  
python run_pipeline.py --lookup-only -n 30

# Preview processing without execution
python run_pipeline.py --dry-run -l rust -n 20
```

## OUTPUT STRUCTURE
The pipeline generates a structured dataset in the specified output directory:

```
data/
├── wasm_cve_complete_dataset.json    # Complete curated dataset
├── wasm_projects/                    # Discovered project metadata
│   └── discovered_wasm_projects.json
├── project_cves/                     # CVE information and mappings
│   └── project_cves.json
├── compiled_wasm/                    # Compiled WASM binaries
│   ├── *.wasm                        # Individual vulnerable binaries
│   └── compilation_results.json     # Compilation metadata
└── repositories/                     # Cloned vulnerable source code
    └── */                           # Individual project repositories
```

## ENVIRONMENT VARIABLES

### Required Setup
- **GITHUB_TOKEN**  
  GitHub personal access token for API access (strongly recommended)

### Optional Configuration
- **WASM_MAX_WORKERS** (default: 20)  
  Number of parallel worker threads

- **WASM_MIN_CONFIDENCE** (default: 0.7)  
  Global minimum confidence score filter

- **WASM_COMPILATION_TIMEOUT** (default: 10)  
  Compilation timeout in minutes

- **WASM_OSV_DELAY** (default: 0.1)  
  Delay between OSV.dev API requests (seconds)

- **WASM_GITHUB_DELAY** (default: 0.3)  
  Delay between GitHub API requests (seconds)

## SYSTEM REQUIREMENTS

### Required Tools
- **Python 3.8+** with pip
- **Git** for repository cloning
- **Rust toolchain** with WASM target: `rustup target add wasm32-unknown-unknown`

### Optional Tools
- **Emscripten** for C/C++ WASM compilation
- **Go** for Go WASM compilation (GOOS=js GOARCH=wasm)

### Dependencies
Install Python dependencies:
```bash
pip install -r requirements.txt
```

## API RATE LIMITS
- **GitHub API**: 5000 requests/hour (authenticated), 60/hour (anonymous)
- **OSV.dev**: No authentication required, built-in rate limiting
- **crates.io**: No authentication required, built-in rate limiting

## EXIT STATUS
- **0**: Successful completion
- **1**: Pipeline error or exception
- **130**: Interrupted by user (Ctrl+C)

## SECURITY CONSIDERATIONS
This tool processes known vulnerable code and generates potentially dangerous binaries. Use in isolated environments and handle outputs with appropriate security measures.

## FILES
- **run_pipeline.py**: Main entry point
- **wasm_cve_pipeline.py**: Core pipeline implementation
- **config/wasm_config.py**: Configuration and rate limiting
- **discovery/**: Project discovery modules  
- **lookup/**: CVE lookup modules
- **compilation/**: WASM compilation modules

## AUTHORS
WASM-V Security Research Pipeline

## SEE ALSO
- OSV.dev Vulnerability Database: https://osv.dev/
- GitHub Security Advisories: https://github.com/advisories
- WebAssembly Security: https://webassembly.org/docs/security/