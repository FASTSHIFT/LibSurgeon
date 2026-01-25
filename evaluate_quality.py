#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LibSurgeon - Decompilation Quality Evaluation Script

This script analyzes decompiled source code to assess quality metrics
and identify potential issues in the reverse engineering output.

Metrics evaluated:
- halt_baddata occurrences (Ghidra analysis failures)
- Code coverage (functions successfully decompiled)
- Symbol quality (demangled vs mangled names)
- Code structure (classes, namespaces detected)
- Suspicious patterns (excessive casts, undefined types)
- Complexity indicators

Usage:
    python evaluate_quality.py /path/to/decompiled/src/
    python evaluate_quality.py /path/to/file.cpp
"""

import argparse
import os
import re
import sys
import glob
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from collections import defaultdict


class Colors:
    """ANSI color codes"""

    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[0;34m"
    CYAN = "\033[0;36m"
    MAGENTA = "\033[0;35m"
    BOLD = "\033[1m"
    NC = "\033[0m"


@dataclass
class FileMetrics:
    """Metrics for a single decompiled file"""

    filepath: str
    filename: str
    lines: int = 0
    functions: int = 0
    classes: int = 0

    # Quality indicators (lower is better for most)
    halt_baddata: int = 0
    undefined_types: int = 0
    excessive_casts: int = 0
    raw_pointers: int = 0
    goto_statements: int = 0
    inline_assembly: int = 0
    stack_chk_fail: int = 0

    # Positive indicators
    demangled_names: int = 0
    namespaces_found: List[str] = field(default_factory=list)
    source_file_refs: List[str] = field(default_factory=list)

    # Issues found
    issues: List[str] = field(default_factory=list)

    @property
    def quality_score(self) -> float:
        """Calculate a quality score (0-100)"""
        score = 100.0

        # Major penalties
        if self.halt_baddata > 0:
            score -= min(50, self.halt_baddata * 10)

        # Minor penalties
        score -= min(10, self.undefined_types * 0.5)
        score -= min(10, self.excessive_casts * 0.2)
        score -= min(5, self.goto_statements * 1)
        score -= min(10, self.inline_assembly * 5)

        # Bonuses
        if self.demangled_names > 0:
            score += min(5, self.demangled_names * 0.1)
        if self.namespaces_found:
            score += 3
        if self.source_file_refs:
            score += 2

        return max(0, min(100, score))


@dataclass
class ProjectMetrics:
    """Aggregate metrics for a decompiled project"""

    directory: str
    total_files: int = 0
    total_lines: int = 0
    total_functions: int = 0
    total_classes: int = 0

    # Aggregated issues
    files_with_halt_baddata: int = 0
    total_halt_baddata: int = 0
    total_undefined_types: int = 0
    total_excessive_casts: int = 0

    # Summary
    avg_quality_score: float = 0.0
    min_quality_score: float = 100.0
    max_quality_score: float = 0.0

    # File details
    file_metrics: List[FileMetrics] = field(default_factory=list)
    worst_files: List[Tuple[str, float]] = field(default_factory=list)


# Patterns for quality detection
PATTERNS = {
    "halt_baddata": re.compile(r"halt_baddata\s*\("),
    "undefined_type": re.compile(r"\bundefined\d*\b"),
    "excessive_cast": re.compile(r"\(\s*\w+\s*\*\s*\)\s*\("),
    "raw_pointer_arithmetic": re.compile(r"\+\s*0x[0-9a-f]+\s*\)"),
    "goto": re.compile(r"\bgoto\s+\w+"),
    "inline_asm": re.compile(r"__asm|asm\s*\("),
    "stack_chk": re.compile(r"__stack_chk_fail"),
    "demangled_name": re.compile(r"::\w+\s*\("),
    "namespace": re.compile(r"namespace\s+(\w+)"),
    "class_comment": re.compile(r"//\s*Class:\s*(\w+)"),
    "function_comment": re.compile(r"//\s*Function:\s*(\w+)"),
    "source_file": re.compile(r"framework/source/[\w/]+\.cpp"),
    "assert_fail": re.compile(r'__assert_fail\s*\([^)]*"([^"]+)"'),
}


def analyze_file(filepath: str) -> FileMetrics:
    """Analyze a single decompiled source file"""
    metrics = FileMetrics(filepath=filepath, filename=os.path.basename(filepath))

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
            lines = content.split("\n")
    except Exception as e:
        metrics.issues.append(f"Could not read file: {e}")
        return metrics

    metrics.lines = len(lines)

    # Count patterns
    metrics.halt_baddata = len(PATTERNS["halt_baddata"].findall(content))
    metrics.undefined_types = len(PATTERNS["undefined_type"].findall(content))
    metrics.excessive_casts = len(PATTERNS["excessive_cast"].findall(content))
    metrics.raw_pointers = len(PATTERNS["raw_pointer_arithmetic"].findall(content))
    metrics.goto_statements = len(PATTERNS["goto"].findall(content))
    metrics.inline_assembly = len(PATTERNS["inline_asm"].findall(content))
    metrics.stack_chk_fail = len(PATTERNS["stack_chk"].findall(content))

    # Positive patterns
    metrics.demangled_names = len(PATTERNS["demangled_name"].findall(content))

    # Find namespaces
    for match in PATTERNS["namespace"].finditer(content):
        ns = match.group(1)
        if ns not in metrics.namespaces_found:
            metrics.namespaces_found.append(ns)

    # Find source file references (from assert messages)
    for match in PATTERNS["source_file"].finditer(content):
        ref = match.group(0)
        if ref not in metrics.source_file_refs:
            metrics.source_file_refs.append(ref)

    # Count classes and functions from comments
    metrics.classes = len(PATTERNS["class_comment"].findall(content))
    metrics.functions = len(PATTERNS["function_comment"].findall(content))

    # Record issues
    if metrics.halt_baddata > 0:
        metrics.issues.append(f"Contains {metrics.halt_baddata} halt_baddata calls")
    if metrics.undefined_types > 50:
        metrics.issues.append(f"High undefined type count: {metrics.undefined_types}")
    if metrics.inline_assembly > 0:
        metrics.issues.append(f"Contains inline assembly: {metrics.inline_assembly}")

    return metrics


def analyze_directory(directory: str, file_pattern: str = "*.cpp") -> ProjectMetrics:
    """Analyze all decompiled files in a directory"""
    project = ProjectMetrics(directory=directory)

    # Find all matching files
    pattern = os.path.join(directory, file_pattern)
    files = sorted(glob.glob(pattern))

    if not files:
        print(
            f"{Colors.YELLOW}Warning: No files matching {file_pattern} in {directory}{Colors.NC}"
        )
        return project

    project.total_files = len(files)
    quality_scores = []

    print(f"{Colors.CYAN}Analyzing {len(files)} files...{Colors.NC}")

    for filepath in files:
        metrics = analyze_file(filepath)
        project.file_metrics.append(metrics)

        # Aggregate
        project.total_lines += metrics.lines
        project.total_functions += metrics.functions
        project.total_classes += metrics.classes
        project.total_halt_baddata += metrics.halt_baddata
        project.total_undefined_types += metrics.undefined_types
        project.total_excessive_casts += metrics.excessive_casts

        if metrics.halt_baddata > 0:
            project.files_with_halt_baddata += 1

        score = metrics.quality_score
        quality_scores.append(score)
        project.min_quality_score = min(project.min_quality_score, score)
        project.max_quality_score = max(project.max_quality_score, score)

    # Calculate averages
    if quality_scores:
        project.avg_quality_score = sum(quality_scores) / len(quality_scores)

    # Find worst files
    scored_files = [(m.filename, m.quality_score) for m in project.file_metrics]
    project.worst_files = sorted(scored_files, key=lambda x: x[1])[:10]

    return project


def print_report(project: ProjectMetrics, verbose: bool = False):
    """Print a formatted quality report"""
    print()
    print("=" * 70)
    print(f"{Colors.BOLD}LibSurgeon Decompilation Quality Report{Colors.NC}")
    print("=" * 70)
    print()

    # Overall Statistics
    print(f"{Colors.BLUE}Overall Statistics:{Colors.NC}")
    print(f"  Directory:        {project.directory}")
    print(f"  Total files:      {project.total_files}")
    print(f"  Total lines:      {project.total_lines:,}")
    print(f"  Total functions:  {project.total_functions:,}")
    print(f"  Total classes:    {project.total_classes:,}")
    print()

    # Quality Score
    score_color = (
        Colors.GREEN
        if project.avg_quality_score >= 80
        else (Colors.YELLOW if project.avg_quality_score >= 50 else Colors.RED)
    )
    print(f"{Colors.BLUE}Quality Score:{Colors.NC}")
    print(
        f"  Average:          {score_color}{project.avg_quality_score:.1f}/100{Colors.NC}"
    )
    print(
        f"  Range:            {project.min_quality_score:.1f} - {project.max_quality_score:.1f}"
    )
    print()

    # Issue Summary
    print(f"{Colors.BLUE}Issue Summary:{Colors.NC}")

    if project.total_halt_baddata == 0:
        print(f"  halt_baddata:     {Colors.GREEN}✓ None{Colors.NC}")
    else:
        print(
            f"  halt_baddata:     {Colors.RED}✗ {project.total_halt_baddata} occurrences in {project.files_with_halt_baddata} files{Colors.NC}"
        )

    print(f"  undefined types:  {project.total_undefined_types:,}")
    print(f"  excessive casts:  {project.total_excessive_casts:,}")
    print()

    # Worst Files
    if project.worst_files:
        print(f"{Colors.BLUE}Lowest Quality Files:{Colors.NC}")
        for filename, score in project.worst_files[:5]:
            color = (
                Colors.GREEN
                if score >= 80
                else (Colors.YELLOW if score >= 50 else Colors.RED)
            )
            print(f"  {color}{score:5.1f}{Colors.NC}  {filename}")
        print()

    # Detailed per-file report
    if verbose:
        print(f"{Colors.BLUE}Per-File Details:{Colors.NC}")
        print("-" * 70)
        print(f"{'File':<40} {'Lines':>8} {'Score':>6} {'Issues':>8}")
        print("-" * 70)

        for m in sorted(project.file_metrics, key=lambda x: x.quality_score):
            score = m.quality_score
            color = (
                Colors.GREEN
                if score >= 80
                else (Colors.YELLOW if score >= 50 else Colors.RED)
            )
            issues = m.halt_baddata + (1 if m.undefined_types > 50 else 0)
            print(
                f"{m.filename:<40} {m.lines:>8} {color}{score:>5.1f}{Colors.NC} {issues:>8}"
            )
        print()

    # Quality Grade
    grade = (
        "A"
        if project.avg_quality_score >= 90
        else (
            "B"
            if project.avg_quality_score >= 80
            else (
                "C"
                if project.avg_quality_score >= 70
                else ("D" if project.avg_quality_score >= 50 else "F")
            )
        )
    )

    grade_color = (
        Colors.GREEN
        if grade in ["A", "B"]
        else (Colors.YELLOW if grade == "C" else Colors.RED)
    )

    print("=" * 70)
    print(f"{Colors.BOLD}Overall Grade: {grade_color}{grade}{Colors.NC}")
    print("=" * 70)

    return grade


def export_json(project: ProjectMetrics, output_path: str):
    """Export metrics to JSON file"""
    data = {
        "directory": project.directory,
        "total_files": project.total_files,
        "total_lines": project.total_lines,
        "total_functions": project.total_functions,
        "avg_quality_score": project.avg_quality_score,
        "files_with_halt_baddata": project.files_with_halt_baddata,
        "total_halt_baddata": project.total_halt_baddata,
        "files": [
            {
                "filename": m.filename,
                "lines": m.lines,
                "quality_score": m.quality_score,
                "halt_baddata": m.halt_baddata,
                "functions": m.functions,
                "namespaces": m.namespaces_found,
                "source_refs": m.source_file_refs,
                "issues": m.issues,
            }
            for m in project.file_metrics
        ],
    }

    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"{Colors.GREEN}Exported to: {output_path}{Colors.NC}")


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate decompilation quality of LibSurgeon output",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Quality Metrics:
  - halt_baddata: Ghidra analysis failures (critical issue)
  - undefined types: Generic type placeholders
  - excessive casts: Complex pointer manipulations
  - demangled names: Successfully recovered C++ symbols
  - source references: Original file paths from asserts

Quality Score (0-100):
  A (90+): Excellent - code is highly readable
  B (80+): Good - minor issues, usable
  C (70+): Fair - needs manual cleanup
  D (50+): Poor - significant issues
  F (<50): Failed - mostly unusable

Examples:
  python evaluate_quality.py ./decompiled_src/
  python evaluate_quality.py ./output/ --verbose
  python evaluate_quality.py ./output/ --json report.json
""",
    )

    parser.add_argument(
        "path", help="Directory containing decompiled files or single file"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed per-file report"
    )
    parser.add_argument(
        "-j", "--json", metavar="FILE", help="Export metrics to JSON file"
    )
    parser.add_argument(
        "-p",
        "--pattern",
        default="*.cpp",
        help="File pattern to match (default: *.cpp)",
    )

    args = parser.parse_args()

    if os.path.isfile(args.path):
        # Single file analysis
        metrics = analyze_file(args.path)
        print(f"\n{Colors.BOLD}File: {metrics.filename}{Colors.NC}")
        print(f"Lines: {metrics.lines}")
        print(f"Quality Score: {metrics.quality_score:.1f}/100")
        print(f"halt_baddata: {metrics.halt_baddata}")
        print(f"Functions: {metrics.functions}")
        if metrics.namespaces_found:
            print(f"Namespaces: {', '.join(metrics.namespaces_found)}")
        if metrics.issues:
            print(f"Issues: {', '.join(metrics.issues)}")
    elif os.path.isdir(args.path):
        # Directory analysis
        project = analyze_directory(args.path, args.pattern)
        grade = print_report(project, args.verbose)

        if args.json:
            export_json(project, args.json)

        # Exit code based on grade
        sys.exit(0 if grade in ["A", "B", "C"] else 1)
    else:
        print(f"{Colors.RED}Error: Path not found: {args.path}{Colors.NC}")
        sys.exit(1)


if __name__ == "__main__":
    main()
