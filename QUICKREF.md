# Wasm-V Quick Reference

## Security Research Workflows

### Dataset Generation
```bash
# Small curated dataset (10 projects)
python run_pipeline.py

# Large research dataset (100 high-confidence projects)
python run_pipeline.py -n 100 -c 0.8

# Critical vulnerabilities only
python run_pipeline.py -s critical -n 25
```

### Exploration & Analysis
```bash
# Discover available projects (no CVE lookup)
python run_pipeline.py --discovery-only -n 50

# CVE research without compilation
python run_pipeline.py --lookup-only -n 30

# Preview what would be processed
python run_pipeline.py --dry-run -l rust -s high
```

### Language-Specific Research
```bash
# Rust WebAssembly vulnerabilities
python run_pipeline.py -l rust -n 30

# Multi-language research
python run_pipeline.py -l rust -l go -l cpp -n 50
```

## Output Structure
```
data/
├── wasm_cve_complete_dataset.json    # Complete curated dataset
├── wasm_projects/                    # Project discovery results
├── project_cves/                     # CVE mappings & metadata
├── compiled_wasm/                    # WASM binaries for analysis
└── repositories/                     # Vulnerable source code
```

## Environment Setup
```bash
# Required dependencies
pip install -r requirements.txt
rustup target add wasm32-unknown-unknown

# Environment configuration
cp .env.example .env
# Edit .env with your GitHub token

# Or set environment variables directly
export GITHUB_TOKEN="your_github_token"
export WASM_MAX_WORKERS=10            # Parallel processing
export WASM_MIN_CONFIDENCE=0.8        # Project quality filter
export WASM_COMPILATION_TIMEOUT=15    # Compilation timeout (min)
```

## API Rate Limits
- **GitHub API**: 5000/hour (authenticated), 60/hour (anonymous)
- **OSV.dev**: No authentication required, 0.1s delay recommended
- **crates.io**: No authentication required, 0.5s delay recommended

## Troubleshooting
```bash
# Verbose debugging
python run_pipeline.py --verbose

# Check environment
python -c "from config.wasm_config import CONFIG; print(CONFIG.GITHUB_TOKEN[:10])"

# Test individual stages
python -c "from discovery.wasm_project_discovery import WasmProjectDiscovery; print('Discovery works')"
```