#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# flake8: noqa: E402
"""
LibSurgeon Test Suite - Debug Info Detection Tests

Tests for DWARF debug information detection and DWARF parser functionality.
"""

import json
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evaluate_quality import PATTERNS, FileMetrics, analyze_directory, analyze_file
from libsurgeon import detect_debug_info, extract_archive

# ============================================================
# Test: Debug Info Detection
# ============================================================


class TestDebugInfoDetection:
    """Tests for DWARF debug information detection"""

    def test_detect_debug_info_import(self):
        """Test that detect_debug_info can be imported"""
        from libsurgeon import DebugInfo, detect_debug_info

        assert detect_debug_info is not None
        assert DebugInfo is not None

    def test_debug_info_dataclass(self):
        """Test DebugInfo dataclass structure"""
        from libsurgeon import DebugInfo

        info = DebugInfo()
        assert info.has_debug is False
        assert info.format == "none"
        assert info.version is None
        assert info.sections == []
        assert info.has_local_vars is False
        assert info.compiler is None

    def test_debug_info_with_values(self):
        """Test DebugInfo with populated values"""
        from libsurgeon import DebugInfo

        info = DebugInfo(
            has_debug=True,
            format="DWARF",
            version="3",
            sections=[".debug_info", ".debug_line", ".debug_abbrev"],
            has_local_vars=True,
            compiler="ARM Compiler 5.06",
        )

        assert info.has_debug is True
        assert info.format == "DWARF"
        assert info.version == "3"
        assert len(info.sections) == 3
        assert ".debug_info" in info.sections
        assert info.has_local_vars is True
        assert "ARM" in info.compiler

    def test_detect_elf_with_debug_sections(self, temp_dir):
        """Test detection of ELF file with debug sections"""
        from libsurgeon import detect_debug_info

        # Create a minimal ELF file with debug section names
        # This is a simplified test - real detection uses readelf
        elf_file = os.path.join(temp_dir, "test_debug.o")
        with open(elf_file, "wb") as f:
            # ELF magic
            f.write(b"\x7fELF")
            # Minimal header padding
            f.write(b"\x01\x01\x01" + b"\x00" * 100)

        # The function should handle this gracefully
        info = detect_debug_info(elf_file)
        assert info is not None
        # May or may not detect debug info depending on readelf availability

    def test_detect_nonexistent_file(self):
        """Test detection on nonexistent file"""
        from libsurgeon import detect_debug_info

        info = detect_debug_info("/nonexistent/path/file.o")
        assert info.has_debug is False
        assert info.format == "none"

    def test_detect_non_elf_file(self, temp_dir):
        """Test detection on non-ELF file"""
        from libsurgeon import detect_debug_info

        text_file = os.path.join(temp_dir, "not_elf.txt")
        with open(text_file, "w") as f:
            f.write("This is not an ELF file")

        info = detect_debug_info(text_file)
        assert info.has_debug is False


# ============================================================
# Test: Debug Info Quality Evaluation
# ============================================================


class TestDebugInfoQualityEvaluation:
    """Tests for debug info quality evaluation metrics"""

    def test_file_metrics_debug_fields(self):
        """Test FileMetrics has debug info fields"""
        metrics = FileMetrics(filepath="test.cpp", filename="test.cpp")
        assert hasattr(metrics, "preserved_var_names")
        assert hasattr(metrics, "auto_generated_vars")
        assert hasattr(metrics, "has_debug_info_comment")
        assert hasattr(metrics, "debug_info_ratio")

    def test_debug_info_ratio_calculation(self):
        """Test debug info ratio calculation"""
        metrics = FileMetrics(filepath="test.cpp", filename="test.cpp")

        # No variables
        assert metrics.debug_info_ratio == 0.0

        # All preserved
        metrics.preserved_var_names = 10
        metrics.auto_generated_vars = 0
        assert metrics.debug_info_ratio == 1.0

        # Half preserved
        metrics.preserved_var_names = 5
        metrics.auto_generated_vars = 5
        assert metrics.debug_info_ratio == 0.5

        # Mostly auto-generated
        metrics.preserved_var_names = 2
        metrics.auto_generated_vars = 8
        assert metrics.debug_info_ratio == 0.2

    def test_quality_score_with_debug_info(self):
        """Test quality score bonus from debug info"""
        # Create metrics with some penalties to see the debug bonus effect
        metrics_no_debug = FileMetrics(filepath="test.cpp", filename="test.cpp")
        metrics_no_debug.undefined_types = 20  # Add penalty
        base_score = metrics_no_debug.quality_score

        # Score with debug info
        metrics_with_debug = FileMetrics(filepath="test.cpp", filename="test.cpp")
        metrics_with_debug.undefined_types = 20  # Same penalty
        metrics_with_debug.preserved_var_names = 20
        metrics_with_debug.auto_generated_vars = 5
        debug_score = metrics_with_debug.quality_score

        # Debug info should increase score
        assert debug_score > base_score

    def test_quality_score_debug_comment_bonus(self):
        """Test quality score bonus from debug info comment"""
        metrics1 = FileMetrics(filepath="test.cpp", filename="test.cpp")
        metrics1.undefined_types = 20  # Add penalty to see bonus effect
        metrics1.has_debug_info_comment = False
        score1 = metrics1.quality_score

        metrics2 = FileMetrics(filepath="test.cpp", filename="test.cpp")
        metrics2.undefined_types = 20  # Same penalty
        metrics2.has_debug_info_comment = True
        score2 = metrics2.quality_score

        # Debug comment should add bonus
        assert score2 > score1

    def test_project_metrics_debug_fields(self):
        """Test ProjectMetrics has debug info aggregation fields"""
        from evaluate_quality import ProjectMetrics

        project = ProjectMetrics(directory="/test")
        assert hasattr(project, "files_with_debug_info")
        assert hasattr(project, "total_preserved_vars")
        assert hasattr(project, "total_auto_generated_vars")
        assert hasattr(project, "avg_debug_info_ratio")

    def test_analyze_file_with_debug_info(self, temp_dir):
        """Test analyzing file with debug info indicators"""
        # Create file with debug info comment and preserved variable names
        content = """/* Debug Information: DWARF */
/* Variable names preserved from original source */

void test_function(int count, float value)
{
    int result = count * 2;
    float temp = value + 1.0f;
    char buffer[32];
    return;
}
"""
        filepath = os.path.join(temp_dir, "debug_test.cpp")
        with open(filepath, "w") as f:
            f.write(content)

        metrics = analyze_file(filepath)

        assert metrics.has_debug_info_comment is True
        assert metrics.preserved_var_names > 0  # count, value, result, temp, buffer

    def test_analyze_file_with_auto_generated_vars(self, temp_dir):
        """Test analyzing file with auto-generated variable names"""
        content = """void test_function(void)
{
    undefined4 local_10;
    undefined8 local_20;
    int iVar1;
    void *pVar2;
    int param_1;
    return;
}
"""
        filepath = os.path.join(temp_dir, "auto_vars.cpp")
        with open(filepath, "w") as f:
            f.write(content)

        metrics = analyze_file(filepath)

        assert metrics.auto_generated_vars > 0

    def test_analyze_file_mixed_vars(self, temp_dir):
        """Test analyzing file with mixed variable names"""
        content = """void render_frame(int width, int height)
{
    int local_10;
    float scale = 1.0f;
    undefined4 uVar1;
    char *buffer;
    int param_1;
    return;
}
"""
        filepath = os.path.join(temp_dir, "mixed_vars.cpp")
        with open(filepath, "w") as f:
            f.write(content)

        metrics = analyze_file(filepath)

        # Should have both preserved and auto-generated
        assert metrics.preserved_var_names > 0  # width, height, scale, buffer
        assert metrics.auto_generated_vars > 0  # local_10, uVar1, param_1
        assert 0 < metrics.debug_info_ratio < 1

    def test_analyze_directory_debug_aggregation(self, temp_dir):
        """Test directory analysis aggregates debug info"""
        # Create files with varying debug info
        file1 = """/* Debug Information: DWARF */
void func1(int count) { int result = count; }
"""
        file2 = """void func2(void) { undefined4 local_10; int iVar1; }
"""

        with open(os.path.join(temp_dir, "file1.cpp"), "w") as f:
            f.write(file1)
        with open(os.path.join(temp_dir, "file2.cpp"), "w") as f:
            f.write(file2)

        project = analyze_directory(temp_dir)

        assert project.files_with_debug_info >= 1
        assert project.total_preserved_vars > 0
        assert project.total_auto_generated_vars > 0

    def test_patterns_debug_info_comment(self):
        """Test debug info comment pattern detection"""
        assert "debug_info_comment" in PATTERNS

        # Should match
        assert PATTERNS["debug_info_comment"].search("/* Debug Information: DWARF */")

        # Should not match
        assert not PATTERNS["debug_info_comment"].search("/* Some other comment */")

    def test_patterns_auto_generated_vars(self):
        """Test auto-generated variable name patterns"""
        # local_XX pattern
        assert PATTERNS["auto_var_local"].search("local_10")
        assert PATTERNS["auto_var_local"].search("local_abc")

        # param_X pattern
        assert PATTERNS["auto_var_param"].search("param_1")
        assert PATTERNS["auto_var_param"].search("param_12")

        # uVar/iVar pattern
        assert PATTERNS["auto_var_uvar"].search("uVar1")
        assert PATTERNS["auto_var_uvar"].search("iVar42")

        # pVar pattern
        assert PATTERNS["auto_var_pvar"].search("pVar1")

        # in_XX pattern
        assert PATTERNS["auto_var_in"].search("in_EAX")
        assert PATTERNS["auto_var_in"].search("in_RAX")

    def test_patterns_meaningful_vars(self):
        """Test meaningful variable name pattern"""
        # Should match meaningful variable declarations
        assert PATTERNS["meaningful_var"].search("int count;")
        assert PATTERNS["meaningful_var"].search("float value = 1.0;")
        assert PATTERNS["meaningful_var"].search("char *buffer;")
        assert PATTERNS["meaningful_var"].search("int width, height)")

        # Should not match auto-generated names
        PATTERNS["meaningful_var"].findall("int local_10;")
        # The pattern might match but we filter in code

    def test_json_export_includes_debug_info(self, temp_dir):
        """Test JSON export includes debug info metrics"""
        from evaluate_quality import export_json

        # Create test file
        content = """/* Debug Information: DWARF */
void test(int value) { int result = value; }
"""
        with open(os.path.join(temp_dir, "test.cpp"), "w") as f:
            f.write(content)

        project = analyze_directory(temp_dir)

        json_path = os.path.join(temp_dir, "report.json")
        export_json(project, json_path)

        with open(json_path, "r") as f:
            data = json.load(f)

        # Check debug info section exists
        assert "debug_info" in data
        assert "files_with_debug_info" in data["debug_info"]
        assert "total_preserved_vars" in data["debug_info"]
        assert "avg_debug_info_ratio" in data["debug_info"]

        # Check per-file debug info
        assert len(data["files"]) > 0
        file_data = data["files"][0]
        assert "preserved_var_names" in file_data
        assert "auto_generated_vars" in file_data
        assert "debug_info_ratio" in file_data


# ============================================================
# Test: Debug Info Integration
# ============================================================


class TestDebugInfoIntegration:
    """Integration tests for debug info detection in decompilation workflow"""

    def test_archive_with_debug_info_detection(self, test_archive, temp_dir):
        """Test that archive processing detects debug info"""
        # This test verifies the integration works
        # Actual debug info detection depends on the test archive content
        extract_dir = os.path.join(temp_dir, "extracted")
        obj_files = extract_archive(test_archive, extract_dir)

        if obj_files:
            # Try to detect debug info in first object file
            obj_path = os.path.join(extract_dir, obj_files[0])
            info = detect_debug_info(obj_path)

            # Should return a valid DebugInfo object
            assert info is not None
            assert hasattr(info, "has_debug")
            assert hasattr(info, "format")


# ============================================================
# Test: DWARF Parser
# ============================================================


class TestDwarfParser:
    """Tests for the DWARF debug info parser"""

    def test_dwarf_parser_import(self):
        """Test that dwarf_parser module can be imported"""
        from dwarf_parser import (
            DwarfFunction,
            DwarfInfo,
            DwarfVariable,
            apply_dwarf_to_code,
            create_variable_mapping,
            generate_variable_comment,
            parse_dwarf_info,
        )

        # Verify classes exist
        assert DwarfInfo is not None
        assert DwarfFunction is not None
        assert DwarfVariable is not None
        assert parse_dwarf_info is not None
        assert apply_dwarf_to_code is not None
        assert create_variable_mapping is not None
        assert generate_variable_comment is not None

    def test_dwarf_variable_dataclass(self):
        """Test DwarfVariable dataclass"""
        from dwarf_parser import DwarfVariable

        var = DwarfVariable(name="test_var", type_name="int", is_parameter=True)
        assert var.name == "test_var"
        assert var.type_name == "int"
        assert var.is_parameter is True
        assert var.location == ""

    def test_dwarf_function_dataclass(self):
        """Test DwarfFunction dataclass"""
        from dwarf_parser import DwarfFunction, DwarfVariable

        func = DwarfFunction(name="test_func")
        assert func.name == "test_func"
        assert func.return_type == "unknown"
        assert func.parameters == []
        assert func.local_variables == []

        # Add parameters and locals
        func.parameters.append(DwarfVariable(name="x", is_parameter=True))
        func.local_variables.append(DwarfVariable(name="temp", is_parameter=False))

        assert len(func.parameters) == 1
        assert len(func.local_variables) == 1

    def test_dwarf_info_dataclass(self):
        """Test DwarfInfo dataclass"""
        from dwarf_parser import DwarfFunction, DwarfInfo

        info = DwarfInfo()
        assert info.functions == {}
        assert info.source_file == ""
        assert info.compiler == ""
        assert info.dwarf_version == 0
        assert info.has_local_vars is False

        # Add a function
        info.functions["test"] = DwarfFunction(name="test")
        assert len(info.functions) == 1

    def test_generate_variable_comment_params_only(self):
        """Test comment generation with parameters only"""
        from dwarf_parser import DwarfFunction, DwarfVariable, generate_variable_comment

        func = DwarfFunction(name="test")
        func.parameters = [
            DwarfVariable(name="x", type_name="int", is_parameter=True),
            DwarfVariable(name="y", type_name="float", is_parameter=True),
        ]

        comment = generate_variable_comment(func)
        assert "Original params:" in comment
        assert "int x" in comment
        assert "float y" in comment

    def test_generate_variable_comment_locals_only(self):
        """Test comment generation with locals only"""
        from dwarf_parser import DwarfFunction, DwarfVariable, generate_variable_comment

        func = DwarfFunction(name="test")
        func.local_variables = [
            DwarfVariable(name="temp", type_name="int", is_parameter=False),
            DwarfVariable(name="result", type_name="float", is_parameter=False),
        ]

        comment = generate_variable_comment(func)
        assert "Original locals:" in comment
        assert "int temp" in comment
        assert "float result" in comment

    def test_generate_variable_comment_both(self):
        """Test comment generation with both params and locals"""
        from dwarf_parser import DwarfFunction, DwarfVariable, generate_variable_comment

        func = DwarfFunction(name="test")
        func.parameters = [DwarfVariable(name="x", type_name="int", is_parameter=True)]
        func.local_variables = [DwarfVariable(name="temp", is_parameter=False)]

        comment = generate_variable_comment(func)
        assert "Original params:" in comment
        assert "Original locals:" in comment

    def test_generate_variable_comment_empty(self):
        """Test comment generation with no variables"""
        from dwarf_parser import DwarfFunction, generate_variable_comment

        func = DwarfFunction(name="test")
        comment = generate_variable_comment(func)
        assert comment == ""

    def test_apply_dwarf_to_code_param_substitution(self):
        """Test parameter name substitution in code"""
        from dwarf_parser import (
            DwarfFunction,
            DwarfInfo,
            DwarfVariable,
            apply_dwarf_to_code,
        )

        info = DwarfInfo()
        func = DwarfFunction(name="test_func")
        func.parameters = [
            DwarfVariable(name="value", type_name="int", is_parameter=True)
        ]
        info.functions["test_func"] = func

        code = """int test_func(int param_1)
{
  return param_1 * 2;
}"""

        result = apply_dwarf_to_code(code, info)
        assert "int test_func(int value)" in result
        assert "return value * 2" in result
        assert "param_1" not in result

    def test_apply_dwarf_to_code_multiple_params(self):
        """Test multiple parameter substitution"""
        from dwarf_parser import (
            DwarfFunction,
            DwarfInfo,
            DwarfVariable,
            apply_dwarf_to_code,
        )

        info = DwarfInfo()
        func = DwarfFunction(name="add")
        func.parameters = [
            DwarfVariable(name="a", type_name="int", is_parameter=True),
            DwarfVariable(name="b", type_name="int", is_parameter=True),
        ]
        info.functions["add"] = func

        code = """int add(int param_1, int param_2)
{
  return param_1 + param_2;
}"""

        result = apply_dwarf_to_code(code, info)
        assert "int add(int a, int b)" in result
        assert "return a + b" in result

    def test_apply_dwarf_to_code_with_locals_comment(self):
        """Test that local variable comments are added"""
        from dwarf_parser import (
            DwarfFunction,
            DwarfInfo,
            DwarfVariable,
            apply_dwarf_to_code,
        )

        info = DwarfInfo()
        func = DwarfFunction(name="compute")
        func.parameters = [DwarfVariable(name="x", is_parameter=True)]
        func.local_variables = [
            DwarfVariable(name="temp", is_parameter=False),
            DwarfVariable(name="result", is_parameter=False),
        ]
        info.functions["compute"] = func

        code = """int compute(int param_1)
{
  int local_1 = param_1 * 2;
  return local_1;
}"""

        result = apply_dwarf_to_code(code, info)
        assert "Original locals:" in result
        assert "temp" in result
        assert "result" in result

    def test_apply_dwarf_to_code_no_match(self):
        """Test code without matching functions is unchanged"""
        from dwarf_parser import DwarfInfo, apply_dwarf_to_code

        info = DwarfInfo()  # Empty info

        code = """int unknown_func(int param_1)
{
  return param_1;
}"""

        result = apply_dwarf_to_code(code, info)
        assert result == code

    def test_create_variable_mapping(self):
        """Test variable mapping creation"""
        from dwarf_parser import (
            DwarfFunction,
            DwarfInfo,
            DwarfVariable,
            create_variable_mapping,
        )

        info = DwarfInfo()
        func = DwarfFunction(name="test")
        func.parameters = [
            DwarfVariable(name="x", is_parameter=True),
            DwarfVariable(name="y", is_parameter=True),
        ]
        info.functions["test"] = func

        mapping = create_variable_mapping(info)
        assert "test" in mapping
        assert mapping["test"]["param_1"] == "x"
        assert mapping["test"]["param_2"] == "y"

    def test_parse_dwarf_info_nonexistent_file(self):
        """Test parsing nonexistent file returns empty info"""
        from dwarf_parser import parse_dwarf_info

        info = parse_dwarf_info("/nonexistent/file.o")
        assert info.functions == {}
        assert info.has_local_vars is False

    def test_apply_dwarf_preserves_structure(self):
        """Test that code structure is preserved after DWARF application"""
        from dwarf_parser import (
            DwarfFunction,
            DwarfInfo,
            DwarfVariable,
            apply_dwarf_to_code,
        )

        info = DwarfInfo()
        func = DwarfFunction(name="process")
        func.parameters = [DwarfVariable(name="data", is_parameter=True)]
        info.functions["process"] = func

        code = """void process(void* param_1)
{
  if (param_1 != NULL) {
    // Do something
    int x = 1;
  }
}"""

        result = apply_dwarf_to_code(code, info)
        # Check structure is preserved
        assert "if (data != NULL)" in result
        assert "// Do something" in result
        assert "int x = 1" in result
