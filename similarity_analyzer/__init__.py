# Similarity Analyzer Python Package

from .similarity_analyzer import (
    DEFAULT_PATTERNS,
    DEFAULT_VARIANTS,
    FileData,
    GroupAnalysis,
    SimilarityResult,
    analyze_group,
    calc_similarity,
    compare_pair,
    find_similar_pairs,
    format_time,
    group_by_pattern,
    load_file,
    normalize_code,
)

__version__ = "1.0.0"
__all__ = [
    "normalize_code",
    "calc_similarity",
    "load_file",
    "compare_pair",
    "group_by_pattern",
    "analyze_group",
    "find_similar_pairs",
    "format_time",
    "FileData",
    "SimilarityResult",
    "GroupAnalysis",
    "DEFAULT_VARIANTS",
    "DEFAULT_PATTERNS",
]
