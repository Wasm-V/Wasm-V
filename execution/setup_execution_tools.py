#!/usr/bin/env python3
"""
FILENAME: execution/setup_execution_tools.py
DESCRIPTION: Setup script for WASM execution and analysis tools
"""

import subprocess
import sys
from pathlib import Path
import urllib.request
import zipfile
import tarfile
import shutil
import platform

def check_command(command: str) -> bool:
    """Check if a command is available"""
    try:
        subprocess.run([command, '--version'], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def install_wasmtime():
    """Install Wasmtime WASM runtime"""
    print("Installing Wasmtime...")
    
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    if system == "darwin":
        if machine == "arm64":
            url = "https://github.com/bytecodealliance/wasmtime/releases/latest/download/wasmtime-v15.0.0-aarch64-macos.tar.xz"
        else:
            url = "https://github.com/bytecodealliance/wasmtime/releases/latest/download/wasmtime-v15.0.0-x86_64-macos.tar.xz"
    elif system == "linux":
        if machine == "aarch64":
            url = "https://github.com/bytecodealliance/wasmtime/releases/latest/download/wasmtime-v15.0.0-aarch64-linux.tar.xz"
        else:
            url = "https://github.com/bytecodealliance/wasmtime/releases/latest/download/wasmtime-v15.0.0-x86_64-linux.tar.xz"
    else:
        print(f"Unsupported system: {system}")
        return False
    
    try:
        # Download and extract
        urllib.request.urlretrieve(url, "wasmtime.tar.xz")
        
        with tarfile.open("wasmtime.tar.xz", "r:xz") as tar:
            tar.extractall()
        
        # Find extracted directory
        extracted_dirs = [d for d in Path(".").iterdir() if d.is_dir() and "wasmtime" in d.name]
        if not extracted_dirs:
            print("Failed to find extracted wasmtime directory")
            return False
        
        wasmtime_dir = extracted_dirs[0]
        wasmtime_binary = wasmtime_dir / "wasmtime"
        
        # Move to /usr/local/bin if possible, otherwise suggest manual installation
        try:
            shutil.move(str(wasmtime_binary), "/usr/local/bin/wasmtime")
            subprocess.run(["chmod", "+x", "/usr/local/bin/wasmtime"])
            print("[SUCCESS] Wasmtime installed to /usr/local/bin/wasmtime")
        except PermissionError:
            print(f"[WARNING] Please manually move {wasmtime_binary} to your PATH")
            print(f"   sudo mv {wasmtime_binary} /usr/local/bin/wasmtime")
            print(f"   sudo chmod +x /usr/local/bin/wasmtime")
        
        # Cleanup
        Path("wasmtime.tar.xz").unlink()
        shutil.rmtree(wasmtime_dir)
        
        return True
        
    except Exception as e:
        print(f"Failed to install wasmtime: {e}")
        return False

def install_wasm_tools():
    """Install wasm-tools for binary analysis"""
    print("Installing wasm-tools...")
    
    try:
        # Try cargo install first
        subprocess.run(["cargo", "install", "wasm-tools"], check=True)
        print("[SUCCESS] wasm-tools installed via cargo")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[WARNING] Failed to install wasm-tools via cargo")
        print("   Please install Rust/Cargo first: https://rustup.rs/")
        return False

def install_git_python():
    """Install GitPython for repository operations"""
    print("Installing GitPython...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "GitPython"], check=True)
        print("[SUCCESS] GitPython installed")
        return True
    except subprocess.CalledProcessError:
        print("[WARNING] Failed to install GitPython")
        return False

def main():
    """Main setup function"""
    print("Setting up WASM execution tools...")
    print("=" * 50)
    
    tools_status = {}
    
    # Check existing tools
    print("\nChecking existing tools:")
    tools_status['wasmtime'] = check_command('wasmtime')
    tools_status['wasm-tools'] = check_command('wasm-tools')
    tools_status['git'] = check_command('git')
    
    for tool, available in tools_status.items():
        status = "[AVAILABLE]" if available else "[MISSING]"
        print(f"   {tool}: {status}")
    
    # Install missing tools
    print("\nInstalling missing tools:")
    
    if not tools_status['wasmtime']:
        install_wasmtime()
    
    if not tools_status['wasm-tools']:
        install_wasm_tools()
    
    if not tools_status['git']:
        print("[WARNING] Git is required but not found. Please install Git manually.")
    
    # Install Python dependencies
    install_git_python()
    
    # Final verification
    print("\n[SUCCESS] Setup complete! Verifying installation:")
    final_status = {
        'wasmtime': check_command('wasmtime'),
        'wasm-tools': check_command('wasm-tools'),
        'git': check_command('git')
    }
    
    all_good = True
    for tool, available in final_status.items():
        status = "[READY]" if available else "[FAILED]"
        print(f"   {tool}: {status}")
        if not available:
            all_good = False
    
    if all_good:
        print("\nAll tools ready for WASM vulnerability testing!")
    else:
        print("\n[WARNING] Some tools failed to install. Please install them manually.")
    
    print("\nUsage:")
    print("   python -c \"from execution.vulnerability_tester import VulnerabilityTester; print('Ready!')\"")

if __name__ == "__main__":
    main()