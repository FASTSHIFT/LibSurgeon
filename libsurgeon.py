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
import re
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
from typing import Dict, List, Optional, Tuple

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

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

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
    decompile_script = os.path.join(script_dir, "ghidra_decompile.py")
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

        batch_result = BatchResult(total=total)
        start_time = time.time()

        if jobs == 1:
            # Sequential processing
            for i, obj_file in enumerate(obj_files, 1):
                basename = os.path.splitext(os.path.basename(obj_file))[0]
                print(f"[{i}/{total}] Processing: {basename}.o")

                result = decompile_object_file(
                    obj_file,
                    src_dir,
                    ghidra_headless,
                    decompile_script,
                    project_dir,
                    skip_existing,
                )

                batch_result.results.append(result)

                if result.success:
                    if result.skipped:
                        print(f"  -> Skipped (exists, {result.lines} lines)")
                        batch_result.skipped += 1
                    else:
                        print(f"  -> Done ({result.lines} lines)")
                    batch_result.success += 1
                    batch_result.total_lines += result.lines
                else:
                    print(f"  -> FAILED: {result.error}")
                    batch_result.failed += 1
                    batch_result.failed_files.append(basename)
        else:
            # Parallel processing
            with ThreadPoolExecutor(max_workers=jobs) as executor:
                futures = {}
                for i, obj_file in enumerate(obj_files, 1):
                    future = executor.submit(
                        decompile_object_file,
                        obj_file,
                        src_dir,
                        ghidra_headless,
                        decompile_script,
                        project_dir,
                        skip_existing,
                    )
                    futures[future] = (i, obj_file)

                for future in as_completed(futures):
                    i, obj_file = futures[future]
                    basename = os.path.splitext(os.path.basename(obj_file))[0]

                    try:
                        result = future.result()
                        batch_result.results.append(result)

                        if result.success:
                            status = "Skipped" if result.skipped else "Done"
                            print(
                                f"[{i}/{total}] {basename}: {status} ({result.lines} lines)"
                            )
                            batch_result.success += 1
                            if result.skipped:
                                batch_result.skipped += 1
                            batch_result.total_lines += result.lines
                        else:
                            print(f"[{i}/{total}] {basename}: FAILED - {result.error}")
                            batch_result.failed += 1
                            batch_result.failed_files.append(basename)
                    except Exception as e:
                        print(f"[{i}/{total}] {basename}: EXCEPTION - {e}")
                        batch_result.failed += 1
                        batch_result.failed_files.append(basename)

        batch_result.duration = time.time() - start_time

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
        f.write(f"## Overview\n\n")
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
        f.write(f"| Metric | Value |\n")
        f.write(f"|--------|-------|\n")
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
  python libsurgeon.py -g /opt/ghidra --evaluate libtouchgfx.a

  # Parallel decompilation
  python libsurgeon.py -g /opt/ghidra -j 4 ./libraries/

  # List archive contents only
  python libsurgeon.py -g /opt/ghidra --list ./my_sdk/

Supported File Types:
  Archives: .a, .lib
  ELF: .so, .elf, .axf, .out, .o
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
            log_error("ELF file processing not yet implemented in Python version")
            log_info("Use libsurgeon.sh for ELF files")
            sys.exit(1)

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

        # ELF files warning
        if scan_result.elf_files:
            log_warn(
                f"Skipping {len(scan_result.elf_files)} ELF files (not supported in Python version)"
            )

        # Generate summary
        if all_results:
            generate_summary(args.output, all_results)
            log_info(f"Summary written to: {os.path.join(args.output, 'SUMMARY.md')}")

        # Print final summary
        total_success = sum(r.success for r in all_results.values())
        total_failed = sum(r.failed for r in all_results.values())

        print()
        print("=" * 60)
        print(f"{Colors.BOLD}Final Summary{Colors.NC}")
        print("=" * 60)
        print(f"  Libraries processed: {len(all_results)}")
        print(f"  Total successful:    {Colors.GREEN}{total_success}{Colors.NC}")
        print(f"  Total failed:        {Colors.RED}{total_failed}{Colors.NC}")
        print(f"  Output:              {args.output}")

        sys.exit(0 if total_failed == 0 else 1)

    else:
        log_error(f"Target not found: {args.target}")
        sys.exit(1)


if __name__ == "__main__":
    main()
