#!/usr/bin/env python3
"""
FILENAME: execution/wasm_executor.py
DESCRIPTION: Automated WASM binary execution and trace collection
"""

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import logging

# Wasmtime binary analysis
import struct

class ExecutionStatus(Enum):
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    NO_ENTRYPOINT = "no_entrypoint"
    RUNTIME_ERROR = "runtime_error"

@dataclass
class ExecutionTrace:
    """Execution trace data for WASM binary"""
    binary_path: Path
    execution_time: float
    status: ExecutionStatus
    stdout: str
    stderr: str
    exit_code: int
    function_calls: List[str]
    memory_usage: Dict[str, int]
    trap_info: Optional[str]
    vulnerability_triggered: bool
    trace_file: Optional[Path]
    
    def to_dict(self):
        result = asdict(self)
        result['binary_path'] = str(self.binary_path)
        result['status'] = self.status.value
        if self.trace_file:
            result['trace_file'] = str(self.trace_file)
        return result

class WasmExecutor:
    """Automated WASM binary executor with trace collection"""
    
    def __init__(self, traces_dir: Path = None):
        self.traces_dir = traces_dir or Path("data/execution_traces")
        self.traces_dir.mkdir(parents=True, exist_ok=True)
        
        # Check for required tools
        self.wasmtime_path = self._find_wasmtime()
        self.wasm_tools_path = self._find_wasm_tools()
        
        self.logger = self._setup_logger()
    
    def _find_wasmtime(self) -> Optional[Path]:
        """Find wasmtime binary"""
        try:
            result = subprocess.run(['which', 'wasmtime'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return Path(result.stdout.strip())
        except:
            pass
        return None
    
    def _find_wasm_tools(self) -> Optional[Path]:
        """Find wasm-tools binary for inspection"""
        try:
            result = subprocess.run(['which', 'wasm-tools'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return Path(result.stdout.strip())
        except:
            pass
        return None
    
    def _setup_logger(self) -> logging.Logger:
        """Setup execution logger"""
        logger = logging.getLogger('wasm_executor')
        logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler(self.traces_dir / 'execution.log')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def analyze_wasm_binary(self, wasm_path: Path) -> Dict[str, Any]:
        """Analyze WASM binary structure to find entry points"""
        analysis = {
            'exports': [],
            'imports': [],
            'functions': [],
            'memory_info': {},
            'start_function': None,
            'main_candidates': []
        }
        
        if not self.wasm_tools_path:
            self.logger.warning("wasm-tools not found, limited analysis available")
            return analysis
        
        try:
            # Get exports (potential entry points)
            result = subprocess.run([
                str(self.wasm_tools_path), 'print', str(wasm_path)
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                wasm_text = result.stdout
                analysis['exports'] = self._extract_exports(wasm_text)
                analysis['imports'] = self._extract_imports(wasm_text)
                analysis['start_function'] = self._extract_start_function(wasm_text)
                analysis['main_candidates'] = self._find_main_candidates(analysis['exports'])
        
        except subprocess.TimeoutExpired:
            self.logger.error(f"Timeout analyzing {wasm_path}")
        except Exception as e:
            self.logger.error(f"Error analyzing {wasm_path}: {e}")
        
        return analysis
    
    def _extract_exports(self, wasm_text: str) -> List[str]:
        """Extract exported functions from WASM text"""
        exports = []
        lines = wasm_text.split('\n')
        
        for line in lines:
            if '(export' in line and 'func' in line:
                # Parse export line: (export "function_name" (func $index))
                parts = line.strip().split('"')
                if len(parts) >= 2:
                    exports.append(parts[1])
        
        return exports
    
    def _extract_imports(self, wasm_text: str) -> List[str]:
        """Extract imported functions"""
        imports = []
        lines = wasm_text.split('\n')
        
        for line in lines:
            if '(import' in line:
                # Parse import lines
                if '"' in line:
                    parts = line.split('"')
                    if len(parts) >= 4:  # module and name
                        imports.append(f"{parts[1]}.{parts[3]}")
        
        return imports
    
    def _extract_start_function(self, wasm_text: str) -> Optional[str]:
        """Extract start function if present"""
        lines = wasm_text.split('\n')
        for line in lines:
            if '(start' in line:
                return line.strip()
        return None
    
    def _find_main_candidates(self, exports: List[str]) -> List[str]:
        """Find likely main/entry functions"""
        candidates = []
        
        # Common entry point names
        main_names = ['main', '_start', 'run', 'execute', 'init', 'entry']
        
        for export in exports:
            export_lower = export.lower()
            if any(name in export_lower for name in main_names):
                candidates.append(export)
        
        # If no obvious candidates, return all exports
        return candidates if candidates else exports
    
    def execute_wasm_with_inputs(self, wasm_path: Path, 
                                function_name: str = None,
                                args: List[str] = None,
                                env_vars: Dict[str, str] = None,
                                timeout: int = 30) -> ExecutionTrace:
        """Execute WASM binary and collect trace"""
        
        if not self.wasmtime_path:
            return ExecutionTrace(
                binary_path=wasm_path,
                execution_time=0,
                status=ExecutionStatus.FAILED,
                stdout="",
                stderr="Wasmtime not found",
                exit_code=-1,
                function_calls=[],
                memory_usage={},
                trap_info=None,
                vulnerability_triggered=False,
                trace_file=None
            )
        
        # Setup trace file
        trace_file = self.traces_dir / f"{wasm_path.stem}_{int(time.time())}.trace"
        
        # Build wasmtime command  
        cmd = [str(self.wasmtime_path), 'run']
        
        # Enable WASM features (use correct wasmtime syntax)
        cmd.extend([
            '-W', 'multi-value=y',
            '-W', 'bulk-memory=y', 
            '-W', 'reference-types=y'
        ])
        
        # Add function invocation if specified
        if function_name:
            cmd.extend(['--invoke', function_name])
        
        cmd.append(str(wasm_path))
        
        # Add arguments
        if args:
            cmd.extend(args)
        
        start_time = time.time()
        
        try:
            # Set up environment
            env = dict(os.environ)
            if env_vars:
                env.update(env_vars)
            
            # Execute with trace collection
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env
            )
            
            execution_time = time.time() - start_time
            
            # Analyze output for vulnerability indicators
            vulnerability_triggered = self._detect_vulnerability_indicators(
                result.stdout, result.stderr, result.returncode
            )
            
            return ExecutionTrace(
                binary_path=wasm_path,
                execution_time=execution_time,
                status=ExecutionStatus.SUCCESS if result.returncode == 0 else ExecutionStatus.FAILED,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
                function_calls=self._extract_function_calls(result.stderr),
                memory_usage=self._extract_memory_usage(result.stderr),
                trap_info=self._extract_trap_info(result.stderr),
                vulnerability_triggered=vulnerability_triggered,
                trace_file=trace_file if trace_file.exists() else None
            )
            
        except subprocess.TimeoutExpired:
            return ExecutionTrace(
                binary_path=wasm_path,
                execution_time=timeout,
                status=ExecutionStatus.TIMEOUT,
                stdout="",
                stderr=f"Execution timed out after {timeout}s",
                exit_code=-1,
                function_calls=[],
                memory_usage={},
                trap_info=None,
                vulnerability_triggered=False,
                trace_file=None
            )
        except Exception as e:
            return ExecutionTrace(
                binary_path=wasm_path,
                execution_time=time.time() - start_time,
                status=ExecutionStatus.RUNTIME_ERROR,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                function_calls=[],
                memory_usage={},
                trap_info=None,
                vulnerability_triggered=False,
                trace_file=None
            )
    
    def _detect_vulnerability_indicators(self, stdout: str, stderr: str, exit_code: int) -> bool:
        """Detect if execution likely triggered a vulnerability"""
        
        # Common vulnerability indicators
        vuln_indicators = [
            'segmentation fault', 'buffer overflow', 'heap corruption',
            'stack overflow', 'memory leak', 'use after free',
            'null pointer dereference', 'integer overflow',
            'trap:', 'unreachable', 'out of bounds', 'assertion failed'
        ]
        
        combined_output = (stdout + stderr).lower()
        
        # Check for indicators
        for indicator in vuln_indicators:
            if indicator in combined_output:
                return True
        
        # Abnormal exit codes often indicate problems
        if exit_code < 0 or exit_code > 127:
            return True
        
        return False
    
    def _extract_function_calls(self, stderr: str) -> List[str]:
        """Extract function call information from debug output"""
        # This would need to be implemented based on wasmtime's debug output format
        return []
    
    def _extract_memory_usage(self, stderr: str) -> Dict[str, int]:
        """Extract memory usage information"""
        # This would need to be implemented based on wasmtime's output
        return {}
    
    def _extract_trap_info(self, stderr: str) -> Optional[str]:
        """Extract trap/error information"""
        if 'trap:' in stderr.lower():
            lines = stderr.split('\n')
            for line in lines:
                if 'trap:' in line.lower():
                    return line.strip()
        return None