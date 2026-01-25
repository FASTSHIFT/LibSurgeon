#!/usr/bin/env python3
"""
Similarity Analyzer - Fast Code Similarity Detection Tool

A high-performance tool for identifying similar source files that can be
unified using macros or templates. Uses rapidfuzz (C++ implementation)
and multiprocessing for optimal performance.

Features:
- Multi-process parallel comparison (bypasses Python GIL)
- rapidfuzz C++ backend (~100x faster than difflib)
- Smart grouping by filename patterns
- Real-time progress display with ETA
- Configurable similarity threshold

Usage:
    python similarity_analyzer.py <source_dir> [options]
    
Examples:
    python similarity_analyzer.py ./src
    python similarity_analyzer.py ./src --find-pairs -t 0.85
    python similarity_analyzer.py ./src -p -w 8 --ext .c .h
"""

import os
import re
import sys
import time
import argparse
from pathlib import Path
from collections import defaultdict
from typing import List, Dict, Tuple, Optional, Set
from multiprocessing import Pool, cpu_count
from dataclasses import dataclass

__version__ = "1.0.0"

# High-performance similarity library
try:
    from rapidfuzz import fuzz
    HAS_RAPIDFUZZ = True
except ImportError:
    HAS_RAPIDFUZZ = False
    from difflib import SequenceMatcher

# Default filename patterns for grouping
DEFAULT_PATTERNS = [
    (r'^(\w+)_(\w+)\.(?:cpp|c|h|hpp)$', '*_variant'),
    (r'^(\w+)(\d+)\.(?:cpp|c|h|hpp)$', '*N'),
]

# Common variant keywords to normalize
DEFAULT_VARIANTS = [
    'RGB565', 'RGB888', 'ARGB8888', 'XRGB8888',
    'RGBA', 'BGRA', 'ARGB', 'ABGR',
    'GRAY2', 'GRAY4', 'GRAY8',
    '8bpp', '16bpp', '24bpp', '32bpp',
    'L8', 'BW',
]


@dataclass
class FileData:
    """Container for file analysis data."""
    filename: str
    lines: int
    normalized: str
    error: Optional[str] = None


@dataclass  
class SimilarityResult:
    """Result of similarity comparison."""
    file1: str
    file2: str
    similarity: float


@dataclass
class GroupAnalysis:
    """Analysis result for a file group."""
    name: str
    files: List[str]
    line_counts: Dict[str, int]
    avg_similarity: float
    total_lines: int
    similarities: List[Tuple[str, str, float]]


def normalize_code(content: str, filename: str, variants: List[str] = None) -> str:
    """
    Normalize code content for comparison.
    
    Removes comments, replaces class/variant names with placeholders,
    and compresses whitespace.
    
    Args:
        content: Source code content
        filename: Original filename (used to extract class name)
        variants: List of variant keywords to normalize
        
    Returns:
        Normalized code string
    """
    if variants is None:
        variants = DEFAULT_VARIANTS
    
    # Remove block comments at start
    content = re.sub(r'^/\*\*.*?\*/', '', content, count=1, flags=re.DOTALL)
    
    # Replace class name from filename
    stem = Path(filename).stem
    content = content.replace(stem, 'CLASS_NAME')
    
    # Replace variant keywords
    for variant in variants:
        content = re.sub(rf'\b{variant}\b', 'VARIANT', content, flags=re.IGNORECASE)
    
    # Compress whitespace
    content = re.sub(r'\s+', ' ', content)
    
    # Limit length for performance
    return content[:50000]


def calc_similarity(s1: str, s2: str) -> float:
    """
    Calculate similarity ratio between two strings.
    
    Uses rapidfuzz if available (10-100x faster), otherwise falls back to difflib.
    
    Args:
        s1: First string
        s2: Second string
        
    Returns:
        Similarity ratio (0.0 to 1.0)
    """
    if HAS_RAPIDFUZZ:
        return fuzz.ratio(s1, s2) / 100.0
    else:
        return SequenceMatcher(None, s1, s2).ratio()


def load_file(args: Tuple[Path, str, List[str]]) -> FileData:
    """
    Load and preprocess a single file.
    
    Args:
        args: Tuple of (source_dir, filename, variants)
        
    Returns:
        FileData object with normalized content
    """
    src_dir, filename, variants = args
    filepath = src_dir / filename
    
    try:
        content = filepath.read_text(errors='ignore')
        normalized = normalize_code(content, filename, variants)
        return FileData(
            filename=filename,
            lines=len(content.split('\n')),
            normalized=normalized,
        )
    except Exception as e:
        return FileData(filename=filename, lines=0, normalized='', error=str(e))


def compare_pair(args: Tuple[str, str, str, str, float]) -> Optional[SimilarityResult]:
    """
    Compare a pair of files for similarity.
    
    Worker function for multiprocessing pool.
    
    Args:
        args: Tuple of (file1, file2, norm1, norm2, threshold)
        
    Returns:
        SimilarityResult if above threshold, None otherwise
    """
    f1, f2, norm1, norm2, threshold = args
    
    # Quick length check
    len1, len2 = len(norm1), len(norm2)
    if max(len1, len2) > min(len1, len2) * 1.8:
        return None
    
    sim = calc_similarity(norm1, norm2)
    if sim >= threshold:
        return SimilarityResult(f1, f2, sim)
    return None


def group_by_pattern(files: List[str], patterns: List[Tuple[str, str]] = None) -> Tuple[Dict[str, List[str]], List[str]]:
    """
    Group files by filename patterns.
    
    Args:
        files: List of filenames
        patterns: List of (regex, group_name) tuples
        
    Returns:
        Tuple of (groups dict, ungrouped files list)
    """
    if patterns is None:
        patterns = DEFAULT_PATTERNS
    
    groups = defaultdict(list)
    ungrouped = []
    
    for f in files:
        matched = False
        for pattern, group_name in patterns:
            if re.match(pattern, f):
                groups[group_name].append(f)
                matched = True
                break
        if not matched:
            ungrouped.append(f)
    
    # Only return groups with 2+ files
    return {k: v for k, v in groups.items() if len(v) > 1}, ungrouped


def analyze_group(files: List[str], file_data: Dict[str, FileData]) -> GroupAnalysis:
    """
    Analyze similarity within a group of files.
    
    Args:
        files: List of filenames in the group
        file_data: Dict of FileData objects
        
    Returns:
        GroupAnalysis with similarity metrics
    """
    file_list = [f for f in files if f in file_data and file_data[f].error is None]
    
    if len(file_list) < 2:
        return GroupAnalysis(
            name='', files=file_list, line_counts={},
            avg_similarity=0, total_lines=0, similarities=[]
        )
    
    # Calculate pairwise similarities
    similarities = []
    for i in range(len(file_list)):
        for j in range(i + 1, len(file_list)):
            f1, f2 = file_list[i], file_list[j]
            sim = calc_similarity(
                file_data[f1].normalized,
                file_data[f2].normalized
            )
            similarities.append((f1, f2, sim))
    
    avg_sim = sum(s[2] for s in similarities) / len(similarities) if similarities else 0
    line_counts = {f: file_data[f].lines for f in file_list}
    
    return GroupAnalysis(
        name='',
        files=file_list,
        line_counts=line_counts,
        avg_similarity=avg_sim,
        total_lines=sum(line_counts.values()),
        similarities=similarities,
    )


def find_similar_pairs(
    file_data: Dict[str, FileData],
    threshold: float,
    num_workers: int,
    show_progress: bool = True
) -> List[SimilarityResult]:
    """
    Find all similar file pairs using multiprocessing.
    
    Args:
        file_data: Dict of FileData objects
        threshold: Minimum similarity threshold
        num_workers: Number of worker processes
        show_progress: Whether to display progress bar
        
    Returns:
        List of SimilarityResult objects sorted by similarity
    """
    files = [f for f, d in file_data.items() if d.error is None]
    
    # Sort by line count and generate pairs
    sorted_files = sorted(files, key=lambda f: file_data[f].lines)
    
    pairs = []
    for i in range(len(sorted_files)):
        for j in range(i + 1, len(sorted_files)):
            f1, f2 = sorted_files[i], sorted_files[j]
            lines1 = file_data[f1].lines
            lines2 = file_data[f2].lines
            
            # Skip if line count difference too large
            if lines2 > lines1 * 2:
                break
            
            pairs.append((
                f1, f2,
                file_data[f1].normalized,
                file_data[f2].normalized,
                threshold
            ))
    
    if show_progress:
        print(f"   Comparing: {len(pairs)} pairs")
    
    if not pairs:
        return []
    
    # Parallel comparison
    start = time.time()
    results = []
    
    with Pool(num_workers) as pool:
        total = len(pairs)
        chunk_size = max(1, total // 100)
        
        for i, result in enumerate(pool.imap_unordered(compare_pair, pairs, chunksize=chunk_size)):
            if result:
                results.append(result)
            
            # Progress display
            if show_progress and ((i + 1) % max(1, total // 50) == 0 or i == total - 1):
                elapsed = time.time() - start
                percent = (i + 1) / total
                eta = elapsed / percent * (1 - percent) if percent > 0 else 0
                speed = (i + 1) / elapsed if elapsed > 0 else 0
                
                bar_len = 30
                filled = int(bar_len * percent)
                bar = '█' * filled + '░' * (bar_len - filled)
                
                sys.stdout.write(f"\r   Progress: [{bar}] {i+1}/{total} ({percent:.0%}) | "
                               f"{elapsed:.1f}s < {eta:.1f}s | {speed:.0f}/s  ")
                sys.stdout.flush()
    
    if show_progress:
        print(f"\n   Done! Found {len(results)} similar pairs")
    
    return sorted(results, key=lambda x: -x.similarity)


def format_time(seconds: float) -> str:
    """Format seconds as human-readable time."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{int(seconds//60)}m{int(seconds%60)}s"
    else:
        return f"{int(seconds//3600)}h{int((seconds%3600)//60)}m"


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Fast code similarity detection tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('src_dir', help='Source directory to analyze')
    parser.add_argument('--impl-dir', '-i', help='Implementation directory (to check which files exist)')
    parser.add_argument('--threshold', '-t', type=float, default=0.80,
                        help='Similarity threshold (0.0-1.0), default: 0.80')
    parser.add_argument('--find-pairs', '-p', action='store_true',
                        help='Find all similar file pairs globally')
    parser.add_argument('--workers', '-w', type=int, default=0,
                        help='Number of worker processes (0=auto)')
    parser.add_argument('--ext', nargs='+', default=['.cpp', '.c', '.h', '.hpp'],
                        help='File extensions to analyze')
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Minimal output')
    parser.add_argument('--version', '-v', action='version', version=f'%(prog)s {__version__}')
    
    args = parser.parse_args()
    
    src_dir = Path(args.src_dir)
    impl_dir = Path(args.impl_dir) if args.impl_dir else None
    num_workers = args.workers if args.workers > 0 else cpu_count()
    
    if not src_dir.exists():
        print(f"Error: Directory not found: {src_dir}")
        sys.exit(1)
    
    total_start = time.time()
    
    if not args.quiet:
        print("=" * 70)
        print(f"Similarity Analyzer v{__version__}")
        print("=" * 70)
        print(f"Backend: {'rapidfuzz (C++)' if HAS_RAPIDFUZZ else 'difflib (slow)'}")
        print(f"Workers: {num_workers}")
        print(f"Threshold: {args.threshold:.0%}")
        print(f"Extensions: {', '.join(args.ext)}")
    
    # Find all matching files
    all_files = []
    for ext in args.ext:
        all_files.extend(f.name for f in src_dir.glob(f'*{ext}'))
    all_files = list(set(all_files))
    
    implemented = set()
    if impl_dir and impl_dir.exists():
        for ext in args.ext:
            implemented.update(f.name for f in impl_dir.glob(f'*{ext}'))
    
    impl_count = sum(1 for f in all_files if f in implemented)
    
    if not args.quiet:
        print(f"\nFiles: {len(all_files)} (implemented: {impl_count}, {impl_count*100//max(1,len(all_files))}%)")
    
    # Load all files
    if not args.quiet:
        print(f"\nLoading files...")
    load_start = time.time()
    
    with Pool(num_workers) as pool:
        load_args = [(src_dir, f, DEFAULT_VARIANTS) for f in all_files]
        results = pool.map(load_file, load_args)
    
    file_data = {r.filename: r for r in results}
    
    if not args.quiet:
        print(f"   Loaded {len(file_data)} files ({time.time()-load_start:.2f}s)")
    
    # Group analysis
    groups, ungrouped = group_by_pattern(all_files)
    
    if not args.quiet:
        print(f"\n{'=' * 70}")
        print("Pattern-based Group Analysis")
        print("=" * 70)
    
    template_candidates = []
    
    for group_name, files in sorted(groups.items(), key=lambda x: -len(x[1])):
        result = analyze_group(files, file_data)
        result.name = group_name
        
        impl_files = [f for f in result.files if f in implemented]
        not_impl = [f for f in result.files if f not in implemented]
        
        if result.avg_similarity >= args.threshold:
            template_candidates.append({
                'group': group_name,
                'result': result,
                'implemented': impl_files,
                'not_implemented': not_impl
            })
        
        if not args.quiet:
            icon = "✅" if result.avg_similarity >= 0.9 else ("🔶" if result.avg_similarity >= 0.7 else "❌")
            print(f"\n{icon} {group_name} ({len(files)} files, {result.avg_similarity:.0%} similar)")
            print(f"   Lines: {result.total_lines} | Impl: {len(impl_files)}, Not: {len(not_impl)}")
            
            for f in sorted(result.files):
                status = "✓" if f in implemented else "○"
                lines = result.line_counts.get(f, 0)
                print(f"     {status} {f} ({lines} lines)")
    
    # Template suggestions
    if not args.quiet:
        print(f"\n{'=' * 70}")
        print(f"Template Candidates (similarity >= {args.threshold:.0%})")
        print("=" * 70)
        
        for item in sorted(template_candidates, key=lambda x: -x['result'].avg_similarity):
            not_impl = item['not_implemented']
            if not not_impl:
                continue
            
            result = item['result']
            savings = result.total_lines - result.total_lines // len(result.files)
            
            print(f"\n📦 {item['group']} ({result.avg_similarity:.0%}, saves ~{savings} lines)")
            for f in not_impl:
                print(f"     ○ {f}")
    
    # Global pair search
    if args.find_pairs:
        if not args.quiet:
            print(f"\n{'=' * 70}")
            print(f"Global Similar File Search (threshold >= {args.threshold:.0%})")
            print("=" * 70)
        
        pairs = find_similar_pairs(file_data, args.threshold, num_workers, not args.quiet)
        
        # Filter already-grouped files
        grouped_files = set()
        for files in groups.values():
            grouped_files.update(files)
        
        new_pairs = [p for p in pairs if p.file1 not in grouped_files or p.file2 not in grouped_files]
        
        if not args.quiet and new_pairs:
            print(f"\nFound {len(new_pairs)} additional similar pairs:")
            for p in new_pairs[:30]:
                impl1 = "✓" if p.file1 in implemented else "○"
                impl2 = "✓" if p.file2 in implemented else "○"
                print(f"  {p.similarity:.0%}: {impl1}{p.file1} <-> {impl2}{p.file2}")
            if len(new_pairs) > 30:
                print(f"  ... and {len(new_pairs) - 30} more")
    
    # Summary
    if not args.quiet:
        print(f"\n{'=' * 70}")
        print("Summary")
        print("=" * 70)
        
        total_template_files = sum(len(item['result'].files) for item in template_candidates)
        total_template_lines = sum(item['result'].total_lines for item in template_candidates)
        potential_savings = sum(
            item['result'].total_lines - item['result'].total_lines // len(item['result'].files)
            for item in template_candidates
        ) if template_candidates else 0
        
        print(f"  Template candidates: {len(template_candidates)} groups, {total_template_files} files")
        if total_template_lines > 0:
            print(f"  Potential savings: ~{potential_savings} lines ({potential_savings * 100 // total_template_lines}%)")
        
        print(f"\n⏱️  Total time: {format_time(time.time() - total_start)}")


if __name__ == '__main__':
    main()
