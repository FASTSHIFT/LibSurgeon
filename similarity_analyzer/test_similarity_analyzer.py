#!/usr/bin/env python3
"""
Unit tests for Similarity Analyzer

Run with: python -m pytest test_similarity_analyzer.py -v
Or: python test_similarity_analyzer.py
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from similarity_analyzer import (
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


class TestNormalizeCode(unittest.TestCase):
    """Tests for code normalization."""
    
    def test_removes_block_comment(self):
        """Block comment at start should be removed."""
        content = """/**
 * This is a header comment
 * With multiple lines
 */
int main() { return 0; }"""
        result = normalize_code(content, "test.cpp")
        self.assertNotIn("header comment", result)
        self.assertIn("main", result)
    
    def test_replaces_class_name(self):
        """Class name from filename should be replaced."""
        content = "class MyClass { void MyClass::method() {} };"
        result = normalize_code(content, "MyClass.cpp")
        self.assertNotIn("MyClass", result)
        self.assertIn("CLASS_NAME", result)
    
    def test_replaces_variant_keywords(self):
        """Variant keywords should be normalized."""
        content = "void draw_RGB565() { RGB888 data; ARGB8888 pixel; }"
        result = normalize_code(content, "test.cpp", DEFAULT_VARIANTS)
        # Note: RGB565 in function name may not be replaced due to word boundary
        self.assertNotIn(" RGB888 ", result)
        self.assertIn("VARIANT", result)
    
    def test_compresses_whitespace(self):
        """Multiple whitespace should be compressed."""
        content = "int    x   =   5;\n\n\n   int y = 10;"
        result = normalize_code(content, "test.cpp")
        self.assertNotIn("    ", result)
        self.assertNotIn("\n\n", result)
    
    def test_limits_length(self):
        """Very long content should be truncated."""
        content = "x" * 100000
        result = normalize_code(content, "test.cpp")
        self.assertLessEqual(len(result), 50000)


class TestCalcSimilarity(unittest.TestCase):
    """Tests for similarity calculation."""
    
    def test_identical_strings(self):
        """Identical strings should have 100% similarity."""
        self.assertEqual(calc_similarity("hello world", "hello world"), 1.0)
    
    def test_completely_different(self):
        """Completely different strings should have low similarity."""
        sim = calc_similarity("aaaaaaa", "bbbbbbb")
        self.assertLess(sim, 0.3)
    
    def test_similar_strings(self):
        """Similar strings should have high similarity."""
        sim = calc_similarity("hello world", "hello worlds")
        self.assertGreater(sim, 0.9)
    
    def test_empty_strings(self):
        """Empty strings should be identical."""
        self.assertEqual(calc_similarity("", ""), 1.0)
    
    def test_symmetry(self):
        """Similarity should be symmetric."""
        s1 = "hello world"
        s2 = "world hello"
        self.assertEqual(calc_similarity(s1, s2), calc_similarity(s2, s1))


class TestLoadFile(unittest.TestCase):
    """Tests for file loading."""
    
    def test_load_valid_file(self):
        """Valid file should be loaded correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "test.cpp"
            filepath.write_text("int main() { return 0; }")
            
            result = load_file((Path(tmpdir), "test.cpp", DEFAULT_VARIANTS))
            
            self.assertEqual(result.filename, "test.cpp")
            self.assertEqual(result.lines, 1)
            self.assertIsNone(result.error)
            self.assertIn("main", result.normalized)
    
    def test_load_nonexistent_file(self):
        """Nonexistent file should return error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = load_file((Path(tmpdir), "nonexistent.cpp", DEFAULT_VARIANTS))
            
            self.assertEqual(result.filename, "nonexistent.cpp")
            self.assertIsNotNone(result.error)
    
    def test_multiline_file(self):
        """Multiline file should count lines correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "test.cpp"
            filepath.write_text("line1\nline2\nline3\nline4\nline5")
            
            result = load_file((Path(tmpdir), "test.cpp", DEFAULT_VARIANTS))
            
            self.assertEqual(result.lines, 5)


class TestComparePair(unittest.TestCase):
    """Tests for pair comparison."""
    
    def test_similar_pair_above_threshold(self):
        """Similar pair above threshold should return result."""
        result = compare_pair(("a.cpp", "b.cpp", "hello world", "hello worlds", 0.8))
        
        self.assertIsNotNone(result)
        self.assertEqual(result.file1, "a.cpp")
        self.assertEqual(result.file2, "b.cpp")
        self.assertGreater(result.similarity, 0.8)
    
    def test_dissimilar_pair_below_threshold(self):
        """Dissimilar pair below threshold should return None."""
        result = compare_pair(("a.cpp", "b.cpp", "aaaa", "bbbb", 0.8))
        
        self.assertIsNone(result)
    
    def test_length_difference_skip(self):
        """Pair with large length difference should be skipped."""
        long_str = "a" * 1000
        short_str = "b" * 100
        result = compare_pair(("a.cpp", "b.cpp", long_str, short_str, 0.5))
        
        self.assertIsNone(result)


class TestGroupByPattern(unittest.TestCase):
    """Tests for pattern-based grouping."""
    
    def test_groups_by_suffix_pattern(self):
        """Files with common patterns should be grouped."""
        files = ["Painter_RGB565.cpp", "Painter_RGB888.cpp", "Painter_ARGB.cpp"]
        patterns = [(r'^(\w+)_(\w+)\.cpp$', 'Painter_*')]
        
        groups, ungrouped = group_by_pattern(files, patterns)
        
        self.assertIn('Painter_*', groups)
        self.assertEqual(len(groups['Painter_*']), 3)
        self.assertEqual(len(ungrouped), 0)
    
    def test_single_file_not_grouped(self):
        """Single matching file should not form a group."""
        files = ["Painter_RGB565.cpp", "Other.cpp"]
        patterns = [(r'^(\w+)_(\w+)\.cpp$', 'Painter_*')]
        
        groups, ungrouped = group_by_pattern(files, patterns)
        
        self.assertEqual(len(groups), 0)  # Need 2+ files for group
    
    def test_unmatched_files(self):
        """Unmatched files should be in ungrouped."""
        files = ["random.cpp", "other.hpp"]
        patterns = [(r'^Painter_(\w+)\.cpp$', 'Painter_*')]
        
        groups, ungrouped = group_by_pattern(files, patterns)
        
        self.assertEqual(len(groups), 0)
        self.assertEqual(len(ungrouped), 2)


class TestAnalyzeGroup(unittest.TestCase):
    """Tests for group analysis."""
    
    def test_analyze_similar_group(self):
        """Similar files should have high average similarity."""
        file_data = {
            'a.cpp': FileData('a.cpp', 100, 'hello world code'),
            'b.cpp': FileData('b.cpp', 100, 'hello world code'),
        }
        
        result = analyze_group(['a.cpp', 'b.cpp'], file_data)
        
        self.assertEqual(len(result.files), 2)
        self.assertEqual(result.avg_similarity, 1.0)
        self.assertEqual(result.total_lines, 200)
    
    def test_analyze_dissimilar_group(self):
        """Dissimilar files should have low average similarity."""
        file_data = {
            'a.cpp': FileData('a.cpp', 100, 'aaaaaaaaaa'),
            'b.cpp': FileData('b.cpp', 100, 'bbbbbbbbbb'),
        }
        
        result = analyze_group(['a.cpp', 'b.cpp'], file_data)
        
        self.assertLess(result.avg_similarity, 0.3)
    
    def test_analyze_empty_group(self):
        """Empty group should return zero values."""
        result = analyze_group([], {})
        
        self.assertEqual(len(result.files), 0)
        self.assertEqual(result.avg_similarity, 0)
        self.assertEqual(result.total_lines, 0)
    
    def test_skips_error_files(self):
        """Files with errors should be skipped."""
        file_data = {
            'a.cpp': FileData('a.cpp', 100, 'hello'),
            'b.cpp': FileData('b.cpp', 0, '', error='File not found'),
        }
        
        result = analyze_group(['a.cpp', 'b.cpp'], file_data)
        
        self.assertEqual(len(result.files), 1)


class TestFormatTime(unittest.TestCase):
    """Tests for time formatting."""
    
    def test_seconds(self):
        """Short durations should show seconds."""
        self.assertEqual(format_time(5.5), "5.5s")
        self.assertEqual(format_time(59.9), "59.9s")
    
    def test_minutes(self):
        """Medium durations should show minutes."""
        self.assertEqual(format_time(60), "1m0s")
        self.assertEqual(format_time(125), "2m5s")
    
    def test_hours(self):
        """Long durations should show hours."""
        self.assertEqual(format_time(3600), "1h0m")
        self.assertEqual(format_time(3725), "1h2m")


class TestIntegration(unittest.TestCase):
    """Integration tests with real files."""
    
    def test_full_workflow(self):
        """Test complete workflow with temp files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create similar files
            for name in ["DrawerRGB565.cpp", "DrawerRGB888.cpp"]:
                path = Path(tmpdir) / name
                path.write_text(f"""/**
 * Auto-generated file
 */
class {Path(name).stem} {{
    void draw() {{
        // Draw RGB565 pixels
        for (int i = 0; i < 100; i++) {{
            pixel = getRGB565();
        }}
    }}
}};
""")
            
            # Create a different file
            (Path(tmpdir) / "Other.cpp").write_text("completely different content here")
            
            # Load files
            from multiprocessing import Pool
            files = ["DrawerRGB565.cpp", "DrawerRGB888.cpp", "Other.cpp"]
            
            with Pool(2) as pool:
                args = [(Path(tmpdir), f, DEFAULT_VARIANTS) for f in files]
                results = pool.map(load_file, args)
            
            file_data = {r.filename: r for r in results}
            
            # Similar files should have high similarity
            sim = calc_similarity(
                file_data["DrawerRGB565.cpp"].normalized,
                file_data["DrawerRGB888.cpp"].normalized
            )
            self.assertGreater(sim, 0.9)
            
            # Different file should have low similarity
            sim_diff = calc_similarity(
                file_data["DrawerRGB565.cpp"].normalized,
                file_data["Other.cpp"].normalized
            )
            self.assertLess(sim_diff, 0.5)


if __name__ == '__main__':
    unittest.main(verbosity=2)
