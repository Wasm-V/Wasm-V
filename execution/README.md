# WASM Vulnerability Execution & Testing

This module enables **automated execution and vulnerability testing** of compiled WASM binaries, answering your key question: "How do I execute these binaries and collect traces from good vs bad versions?"

## What This Solves

- **Automated WASM execution** without browser dependency
- **Vulnerability trigger detection** through dynamic analysis
- **Comparative analysis** between vulnerable and patched versions
- **Execution trace collection** for security research
- **Input fuzzing** tailored to vulnerability types

## Setup

### 1. Install Execution Tools
```bash
# Automated setup (recommended)
python run_pipeline.py --setup-execution

# Manual setup
curl https://wasmtime.dev/install.sh -sSf | bash
cargo install wasm-tools
```

### 2. Install Python Dependencies
```bash
pip install GitPython>=3.1.0
```

## Usage

### Basic Vulnerability Testing
```bash
# Generate dataset with vulnerability testing
python run_pipeline.py --test-vulnerabilities -n 10

# Just setup tools
python run_pipeline.py --setup-execution
```

### Programmatic Usage
```python
from execution.vulnerability_tester import VulnerabilityTester
from execution.wasm_executor import WasmExecutor

# Test all compiled vulnerabilities
tester = VulnerabilityTester(
    compiled_wasm_dir=Path("data/compiled_wasm"),
    output_dir=Path("data/vulnerability_tests")
)

test_results = tester.test_all_vulnerabilities(cves)

# Individual binary execution
executor = WasmExecutor()
trace = executor.execute_wasm_with_inputs(
    wasm_path=Path("vulnerable.wasm"),
    function_name="main",
    args=["malicious_input"],
    timeout=30
)

print(f"Vulnerability triggered: {trace.vulnerability_triggered}")
```

## How It Works

### 1. **Binary Analysis**
- Extracts exported functions and entry points
- Identifies main/start functions automatically
- Analyzes WASM structure for execution context

### 2. **Input Generation**
Generates targeted inputs based on vulnerability type:
- **Buffer Overflow**: Long strings, format strings, binary data
- **Integer Overflow**: MAX_INT, MIN_INT, boundary values
- **Path Traversal**: `../../../etc/passwd`, Windows paths
- **SQL Injection**: `'; DROP TABLE`, UNION attacks
- **Format String**: `%x%x%x`, `%n` sequences

### 3. **Execution Strategies**
- **Multiple Entry Points**: Tries main, _start, run, execute
- **Timeout Protection**: Prevents infinite loops
- **Error Capture**: Collects stdout, stderr, exit codes
- **Trap Detection**: WASM-specific error handling

### 4. **Vulnerability Detection**
Identifies vulnerabilities through:
- Abnormal exit codes
- Trap conditions (unreachable, out of bounds)
- Error messages (segfault, buffer overflow)
- Execution time anomalies
- Memory corruption indicators

### 5. **Comparative Analysis**
When both vulnerable and patched versions exist:
- Compiles fixed version from `fixed_commit`
- Executes identical inputs on both versions
- Compares execution results
- Confirms vulnerability through differential analysis

## Output Structure

```
data/vulnerability_tests/
├── vulnerability_test_results.json    # Test results summary
├── traces/                           # Individual execution traces
│   ├── vulnerable_binary_123.trace   # Execution trace files
│   └── execution.log                 # Execution log
└── patched_binaries/                 # Compiled patched versions
    └── *.wasm                        # Fixed versions for comparison
```

## Research Applications

### Vulnerability Confirmation
```python
# Check if compilation actually preserved the vulnerability
test_results = tester.test_all_vulnerabilities(cves)
confirmed = [t for t in test_results if t.vulnerability_confirmed]
print(f"Confirmed vulnerabilities: {len(confirmed)}/{len(test_results)}")
```

### Execution Trace Analysis
```python
# Analyze execution patterns
for test in test_results:
    if test.vulnerable_trace:
        print(f"CVE {test.cve_id}:")
        print(f"  Exit code: {test.vulnerable_trace.exit_code}")
        print(f"  Trap info: {test.vulnerable_trace.trap_info}")
        print(f"  Vuln triggered: {test.vulnerable_trace.vulnerability_triggered}")
```

### Differential Analysis
```python
# Compare vulnerable vs patched execution
for test in test_results:
    if test.patched_trace and test.vulnerable_trace:
        print(f"CVE {test.cve_id} differential:")
        print(f"  Vulnerable exit: {test.vulnerable_trace.exit_code}")
        print(f"  Patched exit: {test.patched_trace.exit_code}")
        print(f"  Confirmed: {test.vulnerability_confirmed}")
```

## Technical Architecture

### Core Components
- **`WasmExecutor`**: Low-level WASM binary execution
- **`VulnerabilityTester`**: High-level vulnerability testing orchestrator
- **Input Generators**: Vulnerability-specific test case generation
- **Trace Collectors**: Execution data capture and analysis

### Runtime Dependencies
- **Wasmtime**: Primary WASM runtime (Rust-based)
- **wasm-tools**: Binary analysis and inspection
- **GitPython**: Repository operations for patched versions

### Execution Flow
```
WASM Binary → Analysis → Entry Point Discovery → Input Generation → 
Execution → Trace Collection → Vulnerability Detection → Comparison
```

## Security Considerations

- **Isolated Execution**: Runs in controlled environment
- **Timeout Protection**: Prevents resource exhaustion
- **Safe Input Handling**: Careful handling of malicious inputs
- **Log Sanitization**: Prevents log injection attacks

## Academic Value

This addresses a critical gap in WebAssembly security research:
- **Dynamic Analysis**: Goes beyond static vulnerability detection
- **Reproducible Results**: Automated execution ensures consistency
- **Quantitative Metrics**: Provides measurable vulnerability confirmation
- **Comparative Studies**: Enables before/after patch analysis

Perfect for your conference paper's experimental validation section!