# Similarity Analyzer Python Package

from .similarity_analyzer import (
    normalize_code,
    calc_similarity,
    load_file,
    compare_pair,
    group_by_pattern,
    analyze_group,
    find_similar_pairs,
    format_time,
    FileData,
    SimilarityResult,
    GroupAnalysis,
    DEFAULT_VARIANTS,
    DEFAULT_PATTERNS,
)

__version__ = "1.0.0"
__all__ = [
    'normalize_code',
    'calc_similarity',
    'load_file',
    'compare_pair',
    'group_by_pattern',
    'analyze_group',
    'find_similar_pairs',
    'format_time',
    'FileData',
    'SimilarityResult',
    'GroupAnalysis',
    'DEFAULT_VARIANTS',
    'DEFAULT_PATTERNS',
]
