#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LibSurgeon - Code Formatting Script

Automatically format Python code using black, isort, and other tools.
Also supports checking mode for CI pipelines.

Usage:
    python format.py                    # Format all Python files
    python format.py --check            # Check formatting without changing
    python format.py --fix              # Format and fix issues
    python format.py file.py            # Format specific file
"""

import argparse
import subprocess
import sys
import os
from pathlib import Path
from typing import List, Tuple


# ============================================================
# Configuration
# ============================================================

# Files and directories to format
INCLUDE_PATHS = [
    "*.py",
    "tests/*.py",
]

# Files and directories to exclude
EXCLUDE_PATHS = [
    "__pycache__",
    ".git",
    "*.egg-info",
    "build",
    "dist",
    ".venv",
    "venv",
]

# Black configuration
BLACK_CONFIG = {
    "line-length": 88,
    "target-version": ["py38", "py39", "py310", "py311"],
}

# isort configuration (compatible with black)
ISORT_CONFIG = {
    "profile": "black",
    "line_length": 88,
}


# ============================================================
# Utility Functions
# ============================================================

def run_command(cmd: List[str], check: bool = False) -> Tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return 1, "", f"Command not found: {cmd[0]}"


def find_python_files(base_dir: str, patterns: List[str]) -> List[str]:
    """Find all Python files matching patterns"""
    files = []
    base_path = Path(base_dir)
    
    for pattern in patterns:
        if "*" in pattern:
            files.extend(str(p) for p in base_path.glob(pattern))
        elif os.path.isfile(os.path.join(base_dir, pattern)):
            files.append(os.path.join(base_dir, pattern))
        elif os.path.isdir(os.path.join(base_dir, pattern)):
            files.extend(str(p) for p in Path(base_dir, pattern).rglob("*.py"))
    
    return sorted(set(files))


def print_header(title: str):
    """Print a section header"""
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}\n")


def print_result(name: str, success: bool, message: str = ""):
    """Print a result with status indicator"""
    status = "✓" if success else "✗"
    color = "\033[92m" if success else "\033[91m"
    reset = "\033[0m"
    
    if message:
        print(f"{color}{status}{reset} {name}: {message}")
    else:
        print(f"{color}{status}{reset} {name}")


# ============================================================
# Formatters
# ============================================================

def check_tool_installed(tool: str) -> bool:
    """Check if a tool is installed"""
    code, _, _ = run_command([tool, "--version"])
    return code == 0


def run_black(files: List[str], check_only: bool = False) -> bool:
    """Run black formatter"""
    if not check_tool_installed("black"):
        print("  Warning: black not installed. Run: pip install black")
        return True
    
    cmd = ["black"]
    
    # Add configuration
    cmd.extend(["--line-length", str(BLACK_CONFIG["line-length"])])
    
    if check_only:
        cmd.append("--check")
        cmd.append("--diff")
    
    cmd.extend(files)
    
    code, stdout, stderr = run_command(cmd)
    
    if stdout:
        print(stdout)
    if stderr and code != 0:
        print(stderr)
    
    return code == 0


def run_isort(files: List[str], check_only: bool = False) -> bool:
    """Run isort import sorter"""
    if not check_tool_installed("isort"):
        print("  Warning: isort not installed. Run: pip install isort")
        return True
    
    cmd = ["isort"]
    
    # Add configuration
    cmd.extend(["--profile", ISORT_CONFIG["profile"]])
    cmd.extend(["--line-length", str(ISORT_CONFIG["line_length"])])
    
    if check_only:
        cmd.append("--check-only")
        cmd.append("--diff")
    
    cmd.extend(files)
    
    code, stdout, stderr = run_command(cmd)
    
    if stdout:
        print(stdout)
    if stderr and code != 0:
        print(stderr)
    
    return code == 0


def run_flake8(files: List[str]) -> bool:
    """Run flake8 linter (check only)"""
    if not check_tool_installed("flake8"):
        print("  Warning: flake8 not installed. Run: pip install flake8")
        return True
    
    cmd = ["flake8"]
    
    # Common ignores compatible with black
    cmd.extend([
        "--max-line-length", "88",
        "--extend-ignore", "E203,E501,W503",
        "--exclude", ",".join(EXCLUDE_PATHS)
    ])
    
    cmd.extend(files)
    
    code, stdout, stderr = run_command(cmd)
    
    if stdout:
        print(stdout)
    if stderr:
        print(stderr)
    
    return code == 0


def run_mypy(files: List[str]) -> bool:
    """Run mypy type checker (check only)"""
    if not check_tool_installed("mypy"):
        print("  Warning: mypy not installed. Run: pip install mypy")
        return True
    
    cmd = ["mypy"]
    
    # Relaxed settings for gradual typing
    cmd.extend([
        "--ignore-missing-imports",
        "--no-strict-optional",
        "--allow-untyped-defs",
    ])
    
    cmd.extend(files)
    
    code, stdout, stderr = run_command(cmd)
    
    if stdout:
        print(stdout)
    if stderr and "error" in stderr.lower():
        print(stderr)
    
    return code == 0


# ============================================================
# Main Functions
# ============================================================

def format_files(files: List[str], check_only: bool = False) -> bool:
    """Format or check all files"""
    all_passed = True
    
    # isort
    print_header("Import Sorting (isort)")
    if run_isort(files, check_only):
        print_result("isort", True, "passed" if check_only else "completed")
    else:
        print_result("isort", False, "issues found")
        all_passed = False
    
    # black
    print_header("Code Formatting (black)")
    if run_black(files, check_only):
        print_result("black", True, "passed" if check_only else "completed")
    else:
        print_result("black", False, "issues found")
        all_passed = False
    
    # Linting (always check-only)
    print_header("Linting (flake8)")
    if run_flake8(files):
        print_result("flake8", True, "no issues")
    else:
        print_result("flake8", False, "issues found")
        if check_only:
            all_passed = False
    
    return all_passed


def main():
    parser = argparse.ArgumentParser(
        description="LibSurgeon Code Formatting Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python format.py                    # Format all files
  python format.py --check            # Check without formatting
  python format.py libsurgeon.py      # Format specific file
  python format.py --lint             # Run linters only

Required tools:
  pip install black isort flake8
"""
    )
    
    parser.add_argument(
        'files',
        nargs='*',
        help='Specific files to format (default: all Python files)'
    )
    parser.add_argument(
        '--check', '-c',
        action='store_true',
        help='Check formatting without making changes'
    )
    parser.add_argument(
        '--lint', '-l',
        action='store_true',
        help='Run linters only (no formatting)'
    )
    parser.add_argument(
        '--fix', '-f',
        action='store_true',
        help='Format files and attempt to fix issues'
    )
    parser.add_argument(
        '--type-check', '-t',
        action='store_true',
        help='Also run mypy type checking'
    )
    
    args = parser.parse_args()
    
    # Determine base directory (script location)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Find files to process
    if args.files:
        files = args.files
    else:
        files = find_python_files(base_dir, INCLUDE_PATHS)
    
    if not files:
        print("No Python files found to process")
        sys.exit(0)
    
    print(f"Processing {len(files)} file(s)...")
    
    # Run tools
    if args.lint:
        # Linting only
        print_header("Linting (flake8)")
        passed = run_flake8(files)
        
        if args.type_check:
            print_header("Type Checking (mypy)")
            passed = run_mypy(files) and passed
        
        sys.exit(0 if passed else 1)
    
    # Format or check
    passed = format_files(files, check_only=args.check)
    
    # Optional type checking
    if args.type_check:
        print_header("Type Checking (mypy)")
        if run_mypy(files):
            print_result("mypy", True, "no errors")
        else:
            print_result("mypy", False, "errors found")
            passed = False
    
    # Summary
    print_header("Summary")
    if passed:
        if args.check:
            print("✓ All checks passed!")
        else:
            print("✓ Formatting complete!")
    else:
        if args.check:
            print("✗ Some checks failed. Run without --check to fix.")
        else:
            print("✗ Some issues could not be automatically fixed.")
    
    sys.exit(0 if passed else 1)


if __name__ == '__main__':
    main()
