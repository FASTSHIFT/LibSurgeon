#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LibSurgeon Test Suite - Quality Evaluation Tests

Tests for code quality evaluation and metrics.
"""

import os

import pytest  # noqa: F401 - used by fixtures

from evaluate_quality import (
    PATTERNS,
    FileMetrics,
    analyze_directory,
    analyze_file,
)


class TestQualityEvaluation:
    """Tests for quality evaluation"""

    def test_analyze_good_file(self, sample_cpp_file):
        """Test analyzing a good quality file"""
        metrics = analyze_file(sample_cpp_file)

        assert metrics.halt_baddata == 0
        assert metrics.lines > 0
        assert metrics.quality_score >= 80
        assert "xxgfx" in metrics.namespaces_found

    def test_analyze_bad_file(self, sample_bad_cpp_file):
        """Test analyzing a file with quality issues"""
        metrics = analyze_file(sample_bad_cpp_file)

        assert metrics.halt_baddata == 2
        assert metrics.goto_statements >= 1
        assert metrics.quality_score < 80
        assert len(metrics.issues) > 0

    def test_analyze_directory(self, sample_cpp_file, sample_bad_cpp_file, temp_dir):
        """Test analyzing a directory of files"""
        project = analyze_directory(temp_dir)

        assert project.total_files == 2
        assert project.files_with_halt_baddata == 1
        assert project.total_halt_baddata == 2
        assert 0 <= project.avg_quality_score <= 100

    def test_analyze_directory_with_c_files(
        self, sample_cpp_file, sample_c_file, temp_dir
    ):
        """Test analyzing a directory with both .c and .cpp files"""
        project = analyze_directory(temp_dir)

        assert project.total_files == 2
        filenames = [m.filename for m in project.file_metrics]
        assert any(".c" in f and ".cpp" not in f for f in filenames)
        assert any(".cpp" in f for f in filenames)

    def test_analyze_directory_cpp_only_pattern(
        self, sample_cpp_file, sample_c_file, temp_dir
    ):
        """Test analyzing directory with explicit *.cpp pattern"""
        project = analyze_directory(temp_dir, file_pattern="*.cpp")

        assert project.total_files == 1
        assert project.file_metrics[0].filename.endswith(".cpp")

    def test_analyze_directory_c_only_pattern(
        self, sample_cpp_file, sample_c_file, temp_dir
    ):
        """Test analyzing directory with explicit *.c pattern"""
        project = analyze_directory(temp_dir, file_pattern="*.c")
        assert project.total_files >= 1

    def test_quality_score_calculation(self):
        """Test quality score calculation"""
        metrics = FileMetrics(filepath="test.cpp", filename="test.cpp")

        metrics.halt_baddata = 0
        metrics.undefined_types = 0
        assert metrics.quality_score >= 95

        metrics.halt_baddata = 5
        assert metrics.quality_score < 60

    def test_pattern_detection(self):
        """Test regex pattern detection"""
        test_code = """
void test() {
    halt_baddata();
    undefined4 x;
    undefined8 y;
    goto LAB_001;
}
"""
        assert len(PATTERNS["halt_baddata"].findall(test_code)) == 1
        assert len(PATTERNS["undefined_type"].findall(test_code)) == 2
        assert len(PATTERNS["goto"].findall(test_code)) == 1


class TestIntegration:
    """Integration tests"""

    def test_full_quality_report(self, temp_dir):
        """Test full quality report generation"""
        for i in range(3):
            content = f"""// File {i}
void func_{i}(void) {{
    int x = {i};
    return;
}}
"""
            with open(os.path.join(temp_dir, f"file_{i}.cpp"), "w") as f:
                f.write(content)

        project = analyze_directory(temp_dir)

        assert project.total_files == 3
        assert project.avg_quality_score > 0


class TestEdgeCases:
    """Edge case tests"""

    def test_empty_directory(self, temp_dir):
        """Test analyzing empty directory"""
        project = analyze_directory(temp_dir)
        assert project.total_files == 0

    def test_nonexistent_file(self):
        """Test analyzing nonexistent file"""
        metrics = analyze_file("/nonexistent/path/file.cpp")
        assert len(metrics.issues) > 0

    def test_empty_file(self, temp_dir):
        """Test analyzing empty file"""
        empty_file = os.path.join(temp_dir, "empty.cpp")
        with open(empty_file, "w") as f:
            f.write("")

        metrics = analyze_file(empty_file)
        # Empty file may report 0 or 1 lines depending on implementation
        assert metrics.lines <= 1
        assert metrics.quality_score >= 0

    def test_binary_file_handling(self, temp_dir):
        """Test handling of binary files"""
        binary_file = os.path.join(temp_dir, "binary.cpp")
        with open(binary_file, "wb") as f:
            f.write(b"\x00\x01\x02\x03\xff\xfe\xfd")

        try:
            metrics = analyze_file(binary_file)
            assert metrics is not None
        except UnicodeDecodeError:
            pass

    def test_unicode_file(self, temp_dir):
        """Test handling of files with unicode content"""
        unicode_file = os.path.join(temp_dir, "unicode.cpp")
        with open(unicode_file, "w", encoding="utf-8") as f:
            f.write("// 中文注释\nvoid test() { return; }\n")

        metrics = analyze_file(unicode_file)
        assert metrics.lines > 0
