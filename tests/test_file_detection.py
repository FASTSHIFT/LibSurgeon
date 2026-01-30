#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LibSurgeon Test Suite - File Type Detection Tests

Tests for file type detection, pattern matching, and basic utilities.
"""

from libsurgeon import (
    MODULE_STRATEGIES,
    Colors,
    FileType,
    draw_progress_bar,
    format_time,
    get_file_type,
    matches_pattern,
)


class TestFileTypeDetection:
    """Tests for file type detection"""

    def test_archive_extensions(self):
        """Test archive file type detection"""
        assert get_file_type("libfoo.a") == FileType.ARCHIVE
        assert get_file_type("libbar.lib") == FileType.ARCHIVE
        assert get_file_type("/path/to/test.a") == FileType.ARCHIVE

    def test_elf_extensions(self):
        """Test ELF file type detection"""
        assert get_file_type("firmware.elf") == FileType.ELF
        assert get_file_type("libfoo.so") == FileType.ELF
        assert get_file_type("module.o") == FileType.ELF
        assert get_file_type("app.axf") == FileType.ELF
        assert get_file_type("program.out") == FileType.ELF

    def test_so_versioned(self):
        """Test versioned .so files"""
        assert get_file_type("libfoo.so.1") == FileType.ELF
        assert get_file_type("libfoo.so.1.2.3") == FileType.ELF

    def test_unknown_extensions(self):
        """Test unknown file types"""
        assert get_file_type("file.txt") == FileType.UNKNOWN
        assert get_file_type("image.png") == FileType.UNKNOWN
        assert get_file_type("code.cpp") == FileType.UNKNOWN


class TestPatternMatching:
    """Tests for pattern matching"""

    def test_exact_match(self):
        """Test exact filename matching"""
        assert matches_pattern("libfoo.a", "libfoo.a") is True
        assert matches_pattern("libfoo.a", "libbar.a") is False

    def test_wildcard_match(self):
        """Test wildcard pattern matching"""
        assert matches_pattern("libfoo.a", "lib*.a") is True
        assert matches_pattern("libfoo.a", "*.a") is True
        assert matches_pattern("libfoo.a", "libfoo.*") is True
        assert matches_pattern("libfoo.a", "*.so") is False

    def test_question_mark(self):
        """Test single character wildcard"""
        assert matches_pattern("libfoo.a", "libfo?.a") is True
        assert matches_pattern("libfoo.a", "lib???.a") is True
        assert matches_pattern("libfoo.a", "lib??.a") is False


class TestTimeFormatting:
    """Tests for time formatting"""

    def test_seconds(self):
        """Test seconds formatting"""
        assert format_time(0) == "0s"
        assert format_time(30) == "30s"
        assert format_time(59) == "59s"

    def test_minutes(self):
        """Test minutes formatting"""
        assert format_time(60) == "1m0s"
        assert format_time(90) == "1m30s"
        assert format_time(3599) == "59m59s"

    def test_hours(self):
        """Test hours formatting"""
        assert format_time(3600) == "1h0m"
        assert format_time(5400) == "1h30m"
        assert format_time(7200) == "2h0m"


class TestProgressBar:
    """Tests for progress bar functions"""

    def test_draw_progress_bar_empty(self):
        """Test empty progress bar"""
        bar = draw_progress_bar(0, 100)
        assert len(bar) == 40
        assert "█" not in bar
        assert bar.count("░") == 40

    def test_draw_progress_bar_full(self):
        """Test full progress bar"""
        bar = draw_progress_bar(100, 100)
        assert len(bar) == 40
        assert bar.count("█") == 40
        assert "░" not in bar

    def test_draw_progress_bar_half(self):
        """Test half-filled progress bar"""
        bar = draw_progress_bar(50, 100)
        assert len(bar) == 40
        assert bar.count("█") == 20
        assert bar.count("░") == 20

    def test_draw_progress_bar_zero_total(self):
        """Test progress bar with zero total"""
        bar = draw_progress_bar(0, 0)
        assert len(bar) == 40
        assert bar.count("░") == 40

    def test_draw_progress_bar_custom_width(self):
        """Test progress bar with custom width"""
        bar = draw_progress_bar(50, 100, width=20)
        assert len(bar) == 20


class TestModuleStrategies:
    """Tests for ELF module grouping strategies"""

    def test_strategies_defined(self):
        """Test that all strategies are defined"""
        assert "prefix" in MODULE_STRATEGIES
        assert "alpha" in MODULE_STRATEGIES
        assert "camelcase" in MODULE_STRATEGIES
        assert "single" in MODULE_STRATEGIES
        assert len(MODULE_STRATEGIES) == 4


class TestColorOutput:
    """Tests for color output"""

    def test_colors_defined(self):
        """Test that all colors are defined"""
        assert hasattr(Colors, "RED")
        assert hasattr(Colors, "GREEN")
        assert hasattr(Colors, "YELLOW")
        assert hasattr(Colors, "BLUE")
        assert hasattr(Colors, "NC")

    def test_colors_disable(self):
        """Test color disable functionality"""
        # Save original values
        orig_red = Colors.RED
        orig_nc = Colors.NC

        # Disable colors
        Colors.disable()

        # Check colors are empty
        assert Colors.RED == ""
        assert Colors.NC == ""

        # Restore (for other tests)
        Colors.RED = orig_red
        Colors.NC = orig_nc
