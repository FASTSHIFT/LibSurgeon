#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LibSurgeon - Static Library & ELF Reverse Engineering Tool

Automated decompilation of .a archive and ELF files to C/C++ source code
using Ghidra Headless mode.

Features:
- Support for .a, .lib archives and .so, .elf, .o, .axf, .out ELF files
- Recursive directory scanning
- Parallel decompilation (configurable jobs)
- Include/Exclude filters
- Quality evaluation integration
- Detailed progress tracking
- Summary reports

Usage:
    python libsurgeon.py -g /path/to/ghidra /target/directory
    python libsurgeon.py -g /path/to/ghidra -o output/ library.a
    python libsurgeon.py -g /path/to/ghidra --evaluate firmware.elf
"""

import argparse
import glob
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

# ============================================================
# Color and Display Utilities
# ============================================================


class Colors:
    """ANSI color codes for terminal output"""

    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[0;34m"
    CYAN = "\033[0;36m"
    MAGENTA = "\033[0;35m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    NC = "\033[0m"  # No Color

    @classmethod
    def disable(cls):
        """Disable colors for non-TTY output"""
        cls.RED = cls.GREEN = cls.YELLOW = cls.BLUE = ""
        cls.CYAN = cls.MAGENTA = cls.BOLD = cls.DIM = cls.NC = ""


def log_info(msg: str):
    print(f"{Colors.GREEN}[INFO]{Colors.NC} {msg}")


def log_warn(msg: str):
    print(f"{Colors.YELLOW}[WARN]{Colors.NC} {msg}")


def log_error(msg: str):
    print(f"{Colors.RED}[ERROR]{Colors.NC} {msg}")


def log_step(msg: str):
    print(f"{Colors.MAGENTA}[STEP]{Colors.NC} {msg}")


def format_time(seconds: int) -> str:
    """Format seconds to human-readable time"""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        mins, secs = divmod(seconds, 60)
        return f"{mins}m{secs}s"
    else:
        hours, remainder = divmod(seconds, 3600)
        mins = remainder // 60
        return f"{hours}h{mins}m"


def print_banner():
    """Print the program banner"""
    print(f"{Colors.BLUE}")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║              LibSurgeon - Static Library Dissector           ║")
    print("║          Automated Reverse Engineering with Ghidra           ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"{Colors.NC}")


def draw_box(title: str, subtitle: str = "", color: str = Colors.BLUE) -> str:
    """Draw a text box with title"""
    width = max(50, len(title) + 6, len(subtitle) + 6)
    width = min(80, width)

    line = "═" * width

    # Center title
    pad_left = (width - len(title)) // 2
    pad_right = width - len(title) - pad_left
    title_line = f"║{' ' * pad_left}{title}{' ' * pad_right}║"

    result = f"{color}╔{line}╗{Colors.NC}\n"
    result += f"{color}{title_line}{Colors.NC}\n"

    if subtitle:
        pad_left = (width - len(subtitle)) // 2
        pad_right = width - len(subtitle) - pad_left
        subtitle_line = f"║{' ' * pad_left}{subtitle}{' ' * pad_right}║"
        result += f"{color}{subtitle_line}{Colors.NC}\n"

    result += f"{color}╚{line}╝{Colors.NC}"
    return result


def draw_progress_bar(current: int, total: int, width: int = 40) -> str:
    """Draw a progress bar"""
    if total == 0:
        return "░" * width

    filled = int(current * width / total)
    empty = width - filled
    return "█" * filled + "░" * empty


def show_progress(
    current: int,
    total: int,
    elapsed: int,
    filename: str = "",
    eta: int = 0,
):
    """Show progress bar with ETA - similar to shell version"""
    if total <= 0:
        return

    percentage = current * 100 // total
    bar = draw_progress_bar(current, total)

    # Build progress line
    progress_line = f"{Colors.CYAN}[{bar}]{Colors.NC} {Colors.BOLD}{percentage}%{Colors.NC} ({current}/{total})"

    # Add time info
    if eta > 0:
        progress_line += f" | Elapsed: {format_time(elapsed)} | ETA: {Colors.YELLOW}{format_time(eta)}{Colors.NC}"
    else:
        progress_line += f" | Elapsed: {format_time(elapsed)}"

    # Clear line and print
    print(f"\r\033[K{progress_line}")

    # Show current file (clear line first to avoid leftover characters)
    if filename:
        print(
            f"\033[K{Colors.DIM}  -> Completed: {Colors.NC}{Colors.GREEN}{filename}{Colors.NC}"
        )
    else:
        print(f"\033[K{Colors.DIM}  -> Processing...{Colors.NC}")

    # Move cursor up 2 lines
    print("\033[2A", end="")


def show_progress_final(total: int, elapsed: int):
    """Show final completed progress bar"""
    bar = draw_progress_bar(total, total)
    print("\r\033[K\n\033[K\n", end="")
    print("\033[2A", end="")
    print(
        f"{Colors.GREEN}[{bar}]{Colors.NC} {Colors.BOLD}100%{Colors.NC} ({total}/{total}) | Total: {format_time(elapsed)}"
    )
    print()


# ============================================================
# File Type Detection
# ============================================================


class FileType(Enum):
    ARCHIVE = "archive"
    ELF = "elf"
    UNKNOWN = "unknown"


# Extension to file type mapping
EXTENSION_MAP = {
    ".a": FileType.ARCHIVE,
    ".lib": FileType.ARCHIVE,
    ".so": FileType.ELF,
    ".elf": FileType.ELF,
    ".axf": FileType.ELF,
    ".out": FileType.ELF,
    ".o": FileType.ELF,
}

# Module grouping strategies for ELF files
MODULE_STRATEGIES = ["prefix", "alpha", "camelcase", "single"]


def get_file_type(filepath: str) -> FileType:
    """Determine file type based on extension"""
    basename = os.path.basename(filepath)

    # Handle .so.* pattern (e.g., libfoo.so.1.2.3)
    if ".so." in basename:
        return FileType.ELF

    ext = os.path.splitext(basename)[1].lower()
    return EXTENSION_MAP.get(ext, FileType.UNKNOWN)


def is_elf_file(filepath: str) -> bool:
    """Check if file is a valid ELF by magic number"""
    try:
        # Follow symlinks
        real_path = os.path.realpath(filepath)
        if not os.path.isfile(real_path):
            return False

        with open(real_path, "rb") as f:
            magic = f.read(4)
            return magic == b"\x7fELF"
    except (IOError, OSError):
        return False


def is_archive_file(filepath: str) -> bool:
    """Check if file is a valid archive by magic number"""
    try:
        with open(filepath, "rb") as f:
            magic = f.read(8)
            return magic == b"!<arch>\n"
    except (IOError, OSError):
        return False


# ============================================================
# File Scanning
# ============================================================


@dataclass
class ScanResult:
    """Result of file scanning"""

    archives: List[str] = field(default_factory=list)
    elf_files: List[str] = field(default_factory=list)
    total_files: int = 0
    scan_time: float = 0.0


def scan_directory(
    directory: str,
    include_patterns: List[str] = None,
    exclude_patterns: List[str] = None,
    recursive: bool = True,
) -> ScanResult:
    """
    Scan directory for supported files.

    Args:
        directory: Directory to scan
        include_patterns: Only include files matching these patterns
        exclude_patterns: Exclude files matching these patterns
        recursive: Whether to scan recursively
    """
    result = ScanResult()
    start_time = time.time()

    # Supported extensions
    patterns = ["*.a", "*.lib", "*.so", "*.so.*", "*.elf", "*.axf", "*.out", "*.o"]

    # Find all matching files
    all_files = []
    for pattern in patterns:
        if recursive:
            search_pattern = os.path.join(directory, "**", pattern)
            all_files.extend(glob.glob(search_pattern, recursive=True))
        else:
            search_pattern = os.path.join(directory, pattern)
            all_files.extend(glob.glob(search_pattern))

    # Apply filters
    for filepath in sorted(set(all_files)):
        basename = os.path.basename(filepath)

        # Check include patterns
        if include_patterns:
            if not any(matches_pattern(basename, p) for p in include_patterns):
                continue

        # Check exclude patterns
        if exclude_patterns:
            if any(matches_pattern(basename, p) for p in exclude_patterns):
                continue

        # Categorize by type
        file_type = get_file_type(filepath)
        if file_type == FileType.ARCHIVE:
            result.archives.append(filepath)
        elif file_type == FileType.ELF:
            result.elf_files.append(filepath)

        result.total_files += 1

    result.scan_time = time.time() - start_time
    return result


def matches_pattern(filename: str, pattern: str) -> bool:
    """Check if filename matches shell-style pattern"""
    import fnmatch

    return fnmatch.fnmatch(filename, pattern)


# ============================================================
# Archive Processing
# ============================================================


def extract_archive(archive_path: str, output_dir: str) -> List[str]:
    """Extract .o files from a .a archive"""
    os.makedirs(output_dir, exist_ok=True)

    # Convert to absolute path before changing directory
    archive_path = os.path.abspath(archive_path)

    orig_dir = os.getcwd()
    try:
        os.chdir(output_dir)
        result = subprocess.run(
            ["ar", "x", archive_path], capture_output=True, text=True
        )

        if result.returncode != 0:
            raise RuntimeError(f"ar extraction failed: {result.stderr}")

        return sorted(glob.glob("*.o"))
    finally:
        os.chdir(orig_dir)


def list_archive_contents(archive_path: str) -> List[str]:
    """List contents of an archive without extracting"""
    result = subprocess.run(["ar", "t", archive_path], capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(f"Failed to list archive: {result.stderr}")

    return result.stdout.strip().split("\n")


# ============================================================
# Decompilation
# ============================================================


@dataclass
class DecompileResult:
    """Result of decompiling a single file"""

    input_file: str
    output_file: str
    success: bool = False
    skipped: bool = False
    lines: int = 0
    error: Optional[str] = None
    duration: float = 0.0


@dataclass
class BatchResult:
    """Result of batch decompilation"""

    total: int = 0
    success: int = 0
    failed: int = 0
    skipped: int = 0
    total_lines: int = 0
    duration: float = 0.0
    results: List[DecompileResult] = field(default_factory=list)
    failed_files: List[str] = field(default_factory=list)


def decompile_object_file(
    obj_file: str,
    output_dir: str,
    ghidra_headless: str,
    decompile_script: str,
    project_dir: str,
    skip_existing: bool = True,
    timeout: int = 300,
) -> DecompileResult:
    """
    Decompile a single object file using Ghidra Headless mode.
    """
    basename = os.path.splitext(os.path.basename(obj_file))[0]
    output_file = os.path.join(output_dir, f"{basename}.cpp")

    result = DecompileResult(input_file=obj_file, output_file=output_file)

    start_time = time.time()

    # Skip if already exists
    if skip_existing and os.path.isfile(output_file):
        with open(output_file, "r") as f:
            result.lines = sum(1 for _ in f)
        result.success = True
        result.skipped = True
        result.duration = time.time() - start_time
        return result

    # Create unique project name
    proj_name = f"proj_{basename}_{os.getpid()}"

    try:
        cmd = [
            ghidra_headless,
            project_dir,
            proj_name,
            "-import",
            obj_file,
            "-postScript",
            decompile_script,
            output_dir,
            "-deleteProject",
        ]

        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        # Check for output file
        temp_output = os.path.join(output_dir, f"{basename}_decompiled.cpp")

        if os.path.isfile(temp_output):
            shutil.move(temp_output, output_file)
            with open(output_file, "r") as f:
                result.lines = sum(1 for _ in f)
            result.success = True
        else:
            result.error = "No output file generated"

    except subprocess.TimeoutExpired:
        result.error = f"Timeout ({timeout}s)"
    except Exception as e:
        result.error = str(e)

    result.duration = time.time() - start_time
    return result


def process_archive(
    archive_path: str,
    output_base: str,
    ghidra_path: str,
    jobs: int = 1,
    skip_existing: bool = True,
    evaluate: bool = False,
) -> BatchResult:
    """
    Process a static library archive.

    Args:
        archive_path: Path to .a archive
        output_base: Base output directory
        ghidra_path: Path to Ghidra installation
        jobs: Number of parallel jobs
        skip_existing: Skip already decompiled files
        evaluate: Run quality evaluation after decompilation
    """
    archive_name = os.path.splitext(os.path.basename(archive_path))[0]
    output_dir = os.path.join(output_base, archive_name)
    src_dir = os.path.join(output_dir, "src")
    logs_dir = os.path.join(output_dir, "logs")

    os.makedirs(src_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)

    print()
    print(draw_box(f"Processing Archive: {archive_name}", f"Jobs: {jobs}"))
    print()

    # Validate Ghidra
    ghidra_headless = os.path.join(ghidra_path, "support", "analyzeHeadless")
    if not os.path.isfile(ghidra_headless):
        raise FileNotFoundError(f"Ghidra analyzeHeadless not found: {ghidra_headless}")

    # Find decompile script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    decompile_script = os.path.join(script_dir, "ghidra_decompile_lib.py")
    if not os.path.isfile(decompile_script):
        raise FileNotFoundError(f"Decompile script not found: {decompile_script}")

    # Extract archive
    temp_extract_dir = tempfile.mkdtemp(prefix="libsurgeon_")
    project_dir = os.path.join(output_dir, ".ghidra_projects")
    os.makedirs(project_dir, exist_ok=True)

    try:
        log_step(f"Extracting archive: {archive_path}")
        extract_archive(archive_path, temp_extract_dir)

        obj_files = sorted(glob.glob(os.path.join(temp_extract_dir, "*.o")))
        total = len(obj_files)

        log_info(f"Found {total} object files")
        print()  # Space for progress bar
        print()

        batch_result = BatchResult(total=total)
        start_time = time.time()
        completed = 0

        def update_batch_result(result: DecompileResult, basename: str):
            """Update batch result with decompile result"""
            nonlocal completed
            batch_result.results.append(result)

            if result.success:
                batch_result.success += 1
                if result.skipped:
                    batch_result.skipped += 1
                batch_result.total_lines += result.lines
            else:
                batch_result.failed += 1
                batch_result.failed_files.append(basename)

            completed += 1
            elapsed = int(time.time() - start_time)
            eta = 0
            if completed > 0:
                avg_time = elapsed / completed
                eta = int((total - completed) * avg_time)

            status = (
                "Skipped"
                if result.skipped
                else ("FAILED" if not result.success else "Done")
            )
            filename = f"{basename}.o ({status}, {result.lines} lines)"
            show_progress(completed, total, elapsed, filename, eta)

        if jobs == 1:
            # Sequential processing
            for obj_file in obj_files:
                basename = os.path.splitext(os.path.basename(obj_file))[0]

                result = decompile_object_file(
                    obj_file,
                    src_dir,
                    ghidra_headless,
                    decompile_script,
                    project_dir,
                    skip_existing,
                )

                update_batch_result(result, basename)
        else:
            # Parallel processing
            with ThreadPoolExecutor(max_workers=jobs) as executor:
                futures = {}
                for obj_file in obj_files:
                    future = executor.submit(
                        decompile_object_file,
                        obj_file,
                        src_dir,
                        ghidra_headless,
                        decompile_script,
                        project_dir,
                        skip_existing,
                    )
                    futures[future] = obj_file

                for future in as_completed(futures):
                    obj_file = futures[future]
                    basename = os.path.splitext(os.path.basename(obj_file))[0]

                    try:
                        result = future.result()
                    except Exception as e:
                        result = DecompileResult(
                            input_file=obj_file,
                            output_file="",
                            success=False,
                            error=str(e),
                        )

                    update_batch_result(result, basename)

        batch_result.duration = time.time() - start_time

        # Show final progress
        show_progress_final(total, int(batch_result.duration))

    finally:
        # Cleanup
        if os.path.isdir(temp_extract_dir):
            shutil.rmtree(temp_extract_dir)

    # Generate README
    generate_archive_readme(archive_name, output_dir, batch_result)

    # Log failed files
    if batch_result.failed_files:
        failed_log = os.path.join(logs_dir, "failed_files.txt")
        with open(failed_log, "w") as f:
            for name in batch_result.failed_files:
                f.write(f"{name}\n")

    # Run quality evaluation
    if evaluate:
        run_quality_evaluation(src_dir, output_dir)

    return batch_result


def generate_archive_readme(name: str, output_dir: str, result: BatchResult):
    """Generate README for decompiled archive"""
    readme_path = os.path.join(output_dir, "README.md")

    with open(readme_path, "w") as f:
        f.write(f"# {name} - Decompiled Archive\n\n")
        f.write("## Overview\n\n")
        f.write(f"- **Source**: {name}.a\n")
        f.write(f"- **Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- **Total object files**: {result.total}\n")
        f.write(f"- **Successfully decompiled**: {result.success}\n")
        f.write(f"- **Failed**: {result.failed}\n")
        f.write(f"- **Total lines of code**: {result.total_lines:,}\n")
        f.write(f"- **Processing time**: {format_time(int(result.duration))}\n\n")

        f.write("## Directory Structure\n\n")
        f.write("```\n")
        f.write(f"{name}/\n")
        f.write("├── src/           # Decompiled C/C++ source files\n")
        f.write("├── include/       # Header files (if found)\n")
        f.write("├── logs/          # Processing logs\n")
        f.write("└── README.md      # This file\n")
        f.write("```\n\n")

        f.write("## Disclaimer\n\n")
        f.write("This code is automatically generated by reverse engineering.\n")
        f.write("It is intended for educational and research purposes only.\n")


# ============================================================
# ELF File Processing
# ============================================================


@dataclass
class ElfResult:
    """Result of processing an ELF file"""

    input_file: str
    output_dir: str
    success: bool = False
    module_count: int = 0
    function_count: int = 0
    total_lines: int = 0
    duration: float = 0.0
    error: Optional[str] = None


def process_elf_file(
    elf_path: str,
    output_base: str,
    ghidra_path: str,
    strategy: str = "prefix",
    timeout: int = 3600,
    evaluate: bool = False,
) -> ElfResult:
    """
    Process an ELF file using Ghidra headless mode.

    Args:
        elf_path: Path to ELF file
        output_base: Base output directory
        ghidra_path: Path to Ghidra installation
        strategy: Module grouping strategy (prefix|alpha|camelcase|single)
        timeout: Timeout in seconds for Ghidra processing
        evaluate: Run quality evaluation after decompilation
    """
    elf_name = os.path.splitext(os.path.basename(elf_path))[0]
    output_dir = os.path.join(output_base, elf_name)
    logs_dir = os.path.join(output_dir, "logs")

    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)

    result = ElfResult(input_file=elf_path, output_dir=output_dir)
    start_time = time.time()

    print()
    print(draw_box(f"Processing ELF: {elf_name}", f"Strategy: {strategy}"))
    print()

    # Validate Ghidra
    ghidra_headless = os.path.join(ghidra_path, "support", "analyzeHeadless")
    if not os.path.isfile(ghidra_headless):
        result.error = f"Ghidra analyzeHeadless not found: {ghidra_headless}"
        return result

    # Find decompile script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    decompile_script = os.path.join(script_dir, "ghidra_decompile_elf.py")
    if not os.path.isfile(decompile_script):
        result.error = f"ELF decompile script not found: {decompile_script}"
        return result

    # Validate ELF file
    if not is_elf_file(elf_path):
        result.error = f"Not a valid ELF file: {elf_path}"
        return result

    log_info(f"ELF File: {elf_path}")
    log_info(f"Output: {output_dir}")
    log_info(f"Module Strategy: {strategy}")

    # Create temp Ghidra project
    temp_project = tempfile.mkdtemp(prefix="libsurgeon_elf_")

    try:
        log_step("Running Ghidra analysis & decompilation...")
        print()

        # Build Ghidra command
        cmd = [
            ghidra_headless,
            temp_project,
            "elf_project",
            "-import",
            elf_path,
            "-processor",
            "ARM:LE:32:Cortex",
            "-cspec",
            "default",
            "-postScript",
            decompile_script,
            output_dir,
            strategy,
            "-deleteProject",
            "-scriptlog",
            os.path.join(logs_dir, "ghidra_script.log"),
        ]

        # Run Ghidra with progress tracking
        log_file = os.path.join(logs_dir, "ghidra_main.log")

        with open(log_file, "w") as log_f:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            total_funcs = 0
            current_func = 0
            analysis_done = False
            last_func_name = ""
            progress_start_time = time.time()

            for line in process.stdout:
                log_f.write(line)
                log_f.flush()

                # Parse progress
                if "[PROGRESS_TOTAL]" in line:
                    try:
                        total_funcs = int(line.split("[PROGRESS_TOTAL]")[1].strip())
                        analysis_done = True
                        print()  # Clear analyzing line
                        log_info(f"Decompiling {total_funcs} functions...")
                        print()  # Space for progress bar
                        print()
                    except (ValueError, IndexError):
                        pass
                elif "[PROGRESS]" in line and analysis_done:
                    try:
                        progress_part = line.split("[PROGRESS]")[1].strip()
                        parts = progress_part.split("/")
                        current_func = int(parts[0])
                        # Extract function name if present
                        if " " in progress_part:
                            last_func_name = progress_part.split(" ", 1)[1].strip()

                        if total_funcs > 0 and current_func % 50 == 0:
                            elapsed = int(time.time() - progress_start_time)
                            eta = 0
                            if current_func > 0:
                                avg_time = elapsed / current_func
                                eta = int((total_funcs - current_func) * avg_time)
                            show_progress(
                                current_func, total_funcs, elapsed, last_func_name, eta
                            )
                    except (ValueError, IndexError):
                        pass
                elif "ANALYZING" in line and not analysis_done:
                    print(
                        f"\r{Colors.DIM}  Ghidra analyzing...{Colors.NC}",
                        end="",
                        flush=True,
                    )

            process.wait()

            # Show final progress
            if total_funcs > 0:
                elapsed = int(time.time() - progress_start_time)
                show_progress_final(total_funcs, elapsed)
            else:
                print()  # Newline after analyzing

            if process.returncode != 0:
                result.error = f"Ghidra process failed (exit code {process.returncode})"
                log_error(f"Check logs at: {logs_dir}")
                return result

    except subprocess.TimeoutExpired:
        result.error = f"Ghidra processing timed out ({timeout}s)"
        return result
    except Exception as e:
        result.error = str(e)
        return result
    finally:
        # Cleanup temp project
        if os.path.isdir(temp_project):
            shutil.rmtree(temp_project)

    # Count results
    src_dir = os.path.join(output_dir, "src")
    include_dir = os.path.join(output_dir, "include")

    if os.path.isdir(src_dir):
        cpp_files = list(Path(src_dir).glob("*.cpp"))
        result.module_count = len(cpp_files)

        # Count lines and functions
        for cpp_file in cpp_files:
            with open(cpp_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                result.total_lines += content.count("\n")
                result.function_count += content.count("// Function:")

    result.success = result.module_count > 0
    result.duration = time.time() - start_time

    if result.success:
        h_count = (
            len(list(Path(include_dir).glob("*.h")))
            if os.path.isdir(include_dir)
            else 0
        )

        print()
        log_info(f"{Colors.GREEN}ELF Processing Complete{Colors.NC}")
        print(f"  Duration:     {format_time(int(result.duration))}")
        print(f"  Source files: {result.module_count} .cpp files")
        print(f"  Header files: {h_count} .h files")
        print(f"  Functions:    {result.function_count}")
        print(f"  Total lines:  {result.total_lines:,}")
        print()

        # Show top modules
        if result.module_count > 0:
            print(f"  {Colors.CYAN}Generated Modules (top 10 by size):{Colors.NC}")
            cpp_files_with_lines = []
            for cpp_file in Path(src_dir).glob("*.cpp"):
                with open(cpp_file, "r", encoding="utf-8", errors="ignore") as f:
                    lines = sum(1 for _ in f)
                cpp_files_with_lines.append((cpp_file.name, lines))

            cpp_files_with_lines.sort(key=lambda x: x[1], reverse=True)
            for name, lines in cpp_files_with_lines[:10]:
                print(f"     - {name} ({lines} lines)")

            if result.module_count > 10:
                print(
                    f"     {Colors.DIM}... and {result.module_count - 10} more modules{Colors.NC}"
                )
            print()

        # Generate README
        generate_elf_readme(elf_name, output_dir, strategy, result)

        # Run quality evaluation
        if evaluate:
            run_quality_evaluation(src_dir, output_dir)
    else:
        result.error = "No output files generated"
        log_error("Decompilation produced no output. Check logs for details.")

    return result


def generate_elf_readme(name: str, output_dir: str, strategy: str, result: ElfResult):
    """Generate README for decompiled ELF"""
    readme_path = os.path.join(output_dir, "README.md")

    with open(readme_path, "w") as f:
        f.write(f"# {name} - Decompiled ELF Output\n\n")
        f.write("## Overview\n\n")
        f.write(f"- **Source**: {os.path.basename(result.input_file)}\n")
        f.write(f"- **Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- **Module Strategy**: {strategy}\n")
        f.write(f"- **Output Modules**: {result.module_count}\n")
        f.write(f"- **Total Functions**: {result.function_count}\n")
        f.write(f"- **Total Lines**: {result.total_lines:,}\n")
        f.write(f"- **Processing Time**: {format_time(int(result.duration))}\n\n")

        f.write(f"## Module Grouping Strategy: {strategy}\n\n")

        if strategy == "prefix":
            f.write(
                "Functions are grouped by their naming prefix. This works best for libraries\n"
            )
            f.write("with consistent naming conventions like:\n")
            f.write("- xxBmp* (Bitmap functions) -> elf_name_xxBmp.cpp\n")
            f.write("- xxFnt* (Font functions) -> elf_name_xxFnt.cpp\n\n")
        elif strategy == "alpha":
            f.write(
                "Functions are grouped alphabetically (A-Z). Useful for very large\n"
            )
            f.write("ELF files as a first-pass organization.\n\n")
        elif strategy == "camelcase":
            f.write(
                "Functions are grouped by extracting CamelCase words from their names.\n"
            )
            f.write("Good for object-oriented code.\n\n")
        elif strategy == "single":
            f.write("All functions are placed in a single output file.\n\n")

        f.write("## Directory Structure\n\n")
        f.write("```\n")
        f.write(f"{name}/\n")
        f.write("├── src/              # Decompiled source code (.cpp files)\n")
        f.write("├── include/          # Header files (.h files)\n")
        f.write("│   ├── _types.h      # Type definitions\n")
        f.write("│   └── _all_headers.h # Master header\n")
        f.write("├── logs/             # Ghidra processing logs\n")
        f.write("├── _INDEX.md         # Complete function index\n")
        f.write("└── README.md         # This file\n")
        f.write("```\n\n")

        # List source files
        src_dir = os.path.join(output_dir, "src")
        if os.path.isdir(src_dir):
            f.write("## Source Files\n\n")
            f.write("### Decompiled Modules (src/)\n\n")

            cpp_files = sorted(Path(src_dir).glob("*.cpp"))
            for cpp_file in cpp_files:
                with open(cpp_file, "r", encoding="utf-8", errors="ignore") as cf:
                    content = cf.read()
                    lines = content.count("\n")
                    funcs = content.count("// Function:")
                f.write(f"- `{cpp_file.name}` - {funcs} functions ({lines} lines)\n")

        f.write("\n## Disclaimer\n\n")
        f.write("This code is automatically generated by reverse engineering.\n")
        f.write("It is intended for educational and research purposes only.\n")


# ============================================================
# Quality Evaluation Integration
# ============================================================


def run_quality_evaluation(src_dir: str, output_dir: str):
    """Run quality evaluation on decompiled source"""
    log_step("Running quality evaluation...")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    eval_script = os.path.join(script_dir, "evaluate_quality.py")

    if not os.path.isfile(eval_script):
        log_warn("Quality evaluation script not found")
        return

    try:
        # Run evaluation
        result = subprocess.run(
            [
                sys.executable,
                eval_script,
                src_dir,
                "--json",
                os.path.join(output_dir, "quality_report.json"),
            ],
            capture_output=True,
            text=True,
        )

        # Print evaluation output
        print(result.stdout)
        if result.stderr:
            print(result.stderr)

    except Exception as e:
        log_warn(f"Quality evaluation failed: {e}")


# ============================================================
# Summary Generation
# ============================================================


def generate_summary(output_dir: str, results: Dict[str, BatchResult]):
    """Generate overall summary report"""
    summary_path = os.path.join(output_dir, "SUMMARY.md")

    total_files = sum(r.total for r in results.values())
    total_success = sum(r.success for r in results.values())
    total_failed = sum(r.failed for r in results.values())
    total_lines = sum(r.total_lines for r in results.values())
    total_duration = sum(r.duration for r in results.values())

    with open(summary_path, "w") as f:
        f.write("# LibSurgeon Decompilation Summary\n\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        f.write("## Overall Statistics\n\n")
        f.write("| Metric | Value |\n")
        f.write("|--------|-------|\n")
        f.write(f"| Total Libraries | {len(results)} |\n")
        f.write(f"| Total Object Files | {total_files} |\n")
        f.write(f"| Successfully Decompiled | {total_success} |\n")
        f.write(f"| Failed | {total_failed} |\n")
        f.write(f"| Total Lines of Code | {total_lines:,} |\n")
        f.write(f"| Total Duration | {format_time(int(total_duration))} |\n\n")

        f.write("## Libraries Processed\n\n")
        for name, result in sorted(results.items()):
            success_rate = (
                (result.success / result.total * 100) if result.total > 0 else 0
            )
            f.write(f"### {name}\n\n")
            f.write(f"- Files: {result.success}/{result.total} ({success_rate:.1f}%)\n")
            f.write(f"- Lines: {result.total_lines:,}\n")
            f.write(f"- Duration: {format_time(int(result.duration))}\n\n")


# ============================================================
# Main Entry Point
# ============================================================


def main():
    parser = argparse.ArgumentParser(
        description="LibSurgeon - Static Library & ELF Reverse Engineering Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process all libraries in a directory
  python libsurgeon.py -g /opt/ghidra ./my_sdk/

  # Process a single archive with quality evaluation
  python libsurgeon.py -g /opt/ghidra --evaluate lib.a

  # Parallel decompilation for archives
  python libsurgeon.py -g /opt/ghidra -j 4 ./libraries/

  # Process an ELF file with prefix-based module grouping
  python libsurgeon.py -g /opt/ghidra ./firmware.elf

  # ELF with different module grouping strategies
  python libsurgeon.py -g /opt/ghidra -m alpha ./firmware.elf
  python libsurgeon.py -g /opt/ghidra -m camelcase ./firmware.elf
  python libsurgeon.py -g /opt/ghidra -m single ./firmware.elf

  # List archive contents only
  python libsurgeon.py -g /opt/ghidra --list ./my_sdk/

Supported File Types:
  Archives: .a, .lib
  ELF: .so, .elf, .axf, .out, .o

Module Grouping Strategies for ELF:
  prefix    - Group by function name prefix (xxBmp*, xxFnt*) [default]
  alpha     - Group by first letter (A-Z)
  camelcase - Group by CamelCase words
  single    - All functions in one file
""",
    )

    parser.add_argument("target", help="Target file or directory to process")
    parser.add_argument(
        "-g", "--ghidra", required=True, help="Path to Ghidra installation (REQUIRED)"
    )
    parser.add_argument(
        "-o",
        "--output",
        default="./libsurgeon_output",
        help="Output directory (default: ./libsurgeon_output)",
    )
    parser.add_argument(
        "-j", "--jobs", type=int, default=1, help="Number of parallel jobs (default: 1)"
    )
    parser.add_argument(
        "-m",
        "--module",
        choices=MODULE_STRATEGIES,
        default="prefix",
        help="Module grouping strategy for ELF: prefix|alpha|camelcase|single (default: prefix)",
    )
    parser.add_argument(
        "-i",
        "--include",
        action="append",
        dest="include_patterns",
        metavar="PATTERN",
        help="Only include files matching pattern (can be used multiple times)",
    )
    parser.add_argument(
        "-e",
        "--exclude",
        action="append",
        dest="exclude_patterns",
        metavar="PATTERN",
        help="Exclude files matching pattern (can be used multiple times)",
    )
    parser.add_argument(
        "--evaluate",
        action="store_true",
        help="Run quality evaluation after decompilation",
    )
    parser.add_argument(
        "--list", action="store_true", help="List file contents without decompiling"
    )
    parser.add_argument(
        "--no-skip", action="store_true", help="Do not skip already decompiled files"
    )
    parser.add_argument(
        "-c",
        "--clean",
        action="store_true",
        help="Clean previous output before processing",
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable colored output"
    )

    args = parser.parse_args()

    # Disable colors if requested or not TTY
    if args.no_color or not sys.stdout.isatty():
        Colors.disable()

    print_banner()

    # Validate Ghidra path
    ghidra_headless = os.path.join(args.ghidra, "support", "analyzeHeadless")
    if not os.path.isfile(ghidra_headless):
        log_error(f"Ghidra analyzeHeadless not found: {ghidra_headless}")
        sys.exit(1)

    log_info(f"Ghidra: {args.ghidra}")
    log_info(f"Output: {args.output}")

    # Clean output if requested
    if args.clean and os.path.isdir(args.output):
        log_step("Cleaning previous output...")
        shutil.rmtree(args.output)

    os.makedirs(args.output, exist_ok=True)

    # Determine target type
    if os.path.isfile(args.target):
        # Single file
        file_type = get_file_type(args.target)

        if args.list:
            if file_type == FileType.ARCHIVE:
                print(f"\n{Colors.CYAN}Archive contents:{Colors.NC}")
                for item in list_archive_contents(args.target):
                    print(f"  {item}")
            else:
                log_warn("--list only supported for archive files")
            sys.exit(0)

        if file_type == FileType.ARCHIVE:
            result = process_archive(
                args.target,
                args.output,
                args.ghidra,
                jobs=args.jobs,
                skip_existing=not args.no_skip,
                evaluate=args.evaluate,
            )

            # Print summary
            print()
            print("=" * 60)
            print(f"{Colors.BOLD}Summary{Colors.NC}")
            print("=" * 60)
            print(f"  Total files:      {result.total}")
            print(f"  Successful:       {Colors.GREEN}{result.success}{Colors.NC}")
            print(f"  Skipped:          {Colors.YELLOW}{result.skipped}{Colors.NC}")
            print(f"  Failed:           {Colors.RED}{result.failed}{Colors.NC}")
            print(f"  Total lines:      {result.total_lines:,}")
            print(f"  Duration:         {format_time(int(result.duration))}")
            print(f"  Output:           {args.output}")

            sys.exit(0 if result.failed == 0 else 1)

        elif file_type == FileType.ELF:
            result = process_elf_file(
                args.target,
                args.output,
                args.ghidra,
                strategy=args.module,
                evaluate=args.evaluate,
            )

            # Print summary
            print()
            print("=" * 60)
            print(f"{Colors.BOLD}Summary{Colors.NC}")
            print("=" * 60)
            print(f"  Modules:          {result.module_count}")
            print(f"  Functions:        {result.function_count}")
            print(f"  Total lines:      {result.total_lines:,}")
            print(f"  Duration:         {format_time(int(result.duration))}")
            print(f"  Output:           {result.output_dir}")

            if result.error:
                log_error(result.error)

            sys.exit(0 if result.success else 1)

        else:
            log_error(f"Unsupported file type: {args.target}")
            sys.exit(1)

    elif os.path.isdir(args.target):
        # Directory scan
        log_step(f"Scanning directory: {args.target}")

        scan_result = scan_directory(
            args.target,
            include_patterns=args.include_patterns,
            exclude_patterns=args.exclude_patterns,
        )

        print()
        log_info(f"Found {len(scan_result.archives)} archives")
        log_info(f"Found {len(scan_result.elf_files)} ELF files")
        log_info(f"Scan time: {scan_result.scan_time:.2f}s")

        if args.list:
            print(f"\n{Colors.CYAN}Archives:{Colors.NC}")
            for f in scan_result.archives:
                print(f"  {f}")
            print(f"\n{Colors.CYAN}ELF files:{Colors.NC}")
            for f in scan_result.elf_files:
                print(f"  {f}")
            sys.exit(0)

        # Process archives
        all_results = {}
        for archive in scan_result.archives:
            try:
                result = process_archive(
                    archive,
                    args.output,
                    args.ghidra,
                    jobs=args.jobs,
                    skip_existing=not args.no_skip,
                    evaluate=args.evaluate,
                )
                name = os.path.splitext(os.path.basename(archive))[0]
                all_results[name] = result
            except Exception as e:
                log_error(f"Failed to process {archive}: {e}")

        # ELF files processing
        elf_results = {}
        for elf_file in scan_result.elf_files:
            try:
                result = process_elf_file(
                    elf_file,
                    args.output,
                    args.ghidra,
                    strategy=args.module,
                    evaluate=args.evaluate,
                )
                name = os.path.splitext(os.path.basename(elf_file))[0]
                elf_results[name] = result
            except Exception as e:
                log_error(f"Failed to process {elf_file}: {e}")

        # Generate summary
        if all_results:
            generate_summary(args.output, all_results)
            log_info(f"Summary written to: {os.path.join(args.output, 'SUMMARY.md')}")

        # Print final summary
        total_success = sum(r.success for r in all_results.values())
        total_failed = sum(r.failed for r in all_results.values())
        elf_success = sum(1 for r in elf_results.values() if r.success)
        elf_failed = sum(1 for r in elf_results.values() if not r.success)

        print()
        print("=" * 60)
        print(f"{Colors.BOLD}Final Summary{Colors.NC}")
        print("=" * 60)
        print(f"  Archives processed:  {len(all_results)}")
        print(f"    Successful:        {Colors.GREEN}{total_success}{Colors.NC}")
        print(f"    Failed:            {Colors.RED}{total_failed}{Colors.NC}")
        print(f"  ELF files processed: {len(elf_results)}")
        print(f"    Successful:        {Colors.GREEN}{elf_success}{Colors.NC}")
        print(f"    Failed:            {Colors.RED}{elf_failed}{Colors.NC}")
        print(f"  Output:              {args.output}")

        has_failures = total_failed > 0 or elf_failed > 0
        sys.exit(0 if not has_failures else 1)

    else:
        log_error(f"Target not found: {args.target}")
        sys.exit(1)


if __name__ == "__main__":
    main()
