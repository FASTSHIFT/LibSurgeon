#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LibSurgeon Test Suite - Ghidra Common Functions Tests

Tests for header file generation, code normalization, and code cleaning.
"""

import os

import pytest  # noqa: F401 - used by fixtures

from ghidra_common import (
    clean_decompiled_code,
    extract_function_signature,
    generate_header_file,
    generate_master_header,
    generate_types_header,
    normalize_code_types,
    sanitize_filename,
)


class TestHeaderGeneration:
    """Tests for header file generation functions in ghidra_common"""

    def test_extract_function_signature_simple(self):
        """Test extracting function signature from simple function"""
        code = """int my_function(int param1, char *param2)
{
    return 42;
}"""
        sig = extract_function_signature(code)
        assert sig is not None
        assert "my_function" in sig
        assert "int" in sig
        assert "param1" in sig

    def test_extract_function_signature_void(self):
        """Test extracting signature from void function"""
        code = """void empty_function(void)
{
}"""
        sig = extract_function_signature(code)
        assert sig is not None
        assert "void" in sig
        assert "empty_function" in sig

    def test_extract_function_signature_multiline(self):
        """Test extracting signature from multiline declaration"""
        code = """static int
multiline_function(int a,
                   int b,
                   int c)
{
    return a + b + c;
}"""
        sig = extract_function_signature(code)
        assert sig is not None
        assert "multiline_function" in sig

    def test_extract_function_signature_with_undefined(self):
        """Test that Ghidra types are normalized in signature"""
        code = """undefined4 process_data(undefined8 input)
{
    return 0;
}"""
        sig = extract_function_signature(code)
        assert sig is not None

    def test_extract_function_signature_empty(self):
        """Test extracting from empty/invalid code"""
        assert extract_function_signature("") is None
        assert extract_function_signature(None) is None
        assert extract_function_signature("   ") is None

    def test_extract_function_signature_variable_decl(self):
        """Test that variable declarations are rejected"""
        code = "int global_var;"
        sig = extract_function_signature(code)
        assert sig is None

    def test_generate_header_file(self, temp_dir):
        """Test generating a header file"""
        func_signatures = [
            ("my_func", "int my_func(int a, int b)"),
            ("another_func", "void another_func(void)"),
        ]
        header_path = generate_header_file(temp_dir, "test_module", func_signatures)

        assert os.path.isfile(header_path)
        assert header_path.endswith(".h")

        with open(header_path, "r") as f:
            content = f.read()

        assert "#ifndef" in content
        assert "#define" in content
        assert "#endif" in content
        assert "my_func" in content
        assert "another_func" in content
        assert 'extern "C"' in content

    def test_generate_header_file_with_source_type(self, temp_dir):
        """Test header file includes correct source type"""
        func_signatures = [("test_func", "int test_func(void)")]
        header_path = generate_header_file(
            temp_dir, "module", func_signatures, "custom source type"
        )

        with open(header_path, "r") as f:
            content = f.read()

        assert "custom source type" in content

    def test_generate_master_header(self, temp_dir):
        """Test generating master header file"""
        modules = ["module_a", "module_b", "module_c"]
        master_path = generate_master_header(temp_dir, modules, "test_program")

        assert os.path.isfile(master_path)
        assert "_all_headers.h" in master_path

        with open(master_path, "r") as f:
            content = f.read()

        assert "#ifndef _ALL_HEADERS_H_" in content
        assert "module_a.h" in content
        assert "module_b.h" in content
        assert "module_c.h" in content

    def test_generate_types_header(self, temp_dir):
        """Test generating types header file"""
        types_path = generate_types_header(temp_dir)

        assert os.path.isfile(types_path)
        assert types_path.endswith("_types.h")

        with open(types_path, "r") as f:
            content = f.read()

        assert "#ifndef _LIBSURGEON_TYPES_H_" in content
        assert "unk8_t" in content
        assert "unk32_t" in content
        assert "typedef" in content


class TestNormalizeCodeTypes:
    """Tests for type normalization functions"""

    def test_normalize_undefined_types(self):
        """Test normalization of Ghidra undefined types"""
        code = "undefined4 x = 0; undefined8 y = 1;"
        normalized = normalize_code_types(code)
        assert "undefined4" not in normalized
        assert "undefined8" not in normalized
        assert "unk32_t" in normalized
        assert "unk64_t" in normalized

    def test_normalize_basic_types(self):
        """Test normalization of Ghidra basic types"""
        code = "dword value; qword large;"
        normalized = normalize_code_types(code)
        assert "uint32_t" in normalized
        assert "uint64_t" in normalized

    def test_normalize_preserves_standard_types(self):
        """Test that standard C types are preserved"""
        code = "int32_t x; uint8_t y; void *ptr;"
        normalized = normalize_code_types(code)
        assert "int32_t" in normalized
        assert "uint8_t" in normalized
        assert "void *" in normalized


class TestSanitizeFilename:
    """Tests for filename sanitization"""

    def test_basic_sanitize(self):
        """Test basic filename sanitization"""
        assert sanitize_filename("hello") == "hello"
        assert sanitize_filename("test_file") == "test_file"

    def test_sanitize_special_chars(self):
        """Test sanitization of special characters"""
        result = sanitize_filename("test/file:name")
        assert "/" not in result
        assert ":" not in result

    def test_sanitize_spaces(self):
        """Test sanitization of spaces"""
        result = sanitize_filename("test file name")
        assert " " not in result


class TestDirectorySeparation:
    """Tests for src/include directory separation"""

    def test_header_files_in_include_dir(self, temp_dir):
        """Test that header files are generated in include directory"""
        src_dir = os.path.join(temp_dir, "src")
        include_dir = os.path.join(temp_dir, "include")
        os.makedirs(src_dir, exist_ok=True)
        os.makedirs(include_dir, exist_ok=True)

        func_signatures = [("test_func", "int test_func(void)")]
        header_path = generate_header_file(include_dir, "module", func_signatures)

        assert os.path.isfile(header_path)
        assert include_dir in header_path
        assert src_dir not in header_path

    def test_source_files_only_in_src_dir(self, temp_dir):
        """Test that source files go to src, headers to include"""
        src_dir = os.path.join(temp_dir, "src")
        include_dir = os.path.join(temp_dir, "include")
        os.makedirs(src_dir, exist_ok=True)
        os.makedirs(include_dir, exist_ok=True)

        source_file = os.path.join(src_dir, "module.cpp")
        with open(source_file, "w") as f:
            f.write("// Source code\nint main() { return 0; }\n")

        header_file = os.path.join(include_dir, "module.h")
        with open(header_file, "w") as f:
            f.write("#ifndef MODULE_H\n#define MODULE_H\n#endif\n")

        src_files = os.listdir(src_dir)
        include_files = os.listdir(include_dir)

        assert "module.cpp" in src_files
        assert "module.h" not in src_files
        assert "module.h" in include_files
        assert "module.cpp" not in include_files

    def test_types_header_in_include_dir(self, temp_dir):
        """Test that _types.h is generated in include directory"""
        include_dir = os.path.join(temp_dir, "include")
        os.makedirs(include_dir, exist_ok=True)

        types_path = generate_types_header(include_dir)

        assert os.path.isfile(types_path)
        assert types_path == os.path.join(include_dir, "_types.h")

    def test_master_header_includes_all_modules(self, temp_dir):
        """Test that master header includes all module headers"""
        include_dir = os.path.join(temp_dir, "include")
        os.makedirs(include_dir, exist_ok=True)

        modules = ["module_a", "module_b", "module_c"]
        for module in modules:
            header_file = os.path.join(include_dir, f"{module}.h")
            with open(header_file, "w") as f:
                f.write(f"// Header for {module}\n")

        master_path = generate_master_header(include_dir, modules, "test_program")

        assert os.path.isfile(master_path)

        with open(master_path, "r") as f:
            content = f.read()

        for module in modules:
            assert f'#include "{module}.h"' in content


class TestCleanDecompiledCode:
    """Tests for clean_decompiled_code function"""

    def test_remove_function_signature_comment(self):
        """Test removal of function signature comments"""
        code = """/* BESplitMatrix(sbematrix const*, sbevec3*, sbequat*, sbevec3*) */
void BESplitMatrix(sbematrix *param_1, sbevec3 *param_2)
{
    int x = 1;
    return;
}"""
        cleaned = clean_decompiled_code(code)
        assert "/* BESplitMatrix" not in cleaned
        assert "void BESplitMatrix" in cleaned

    def test_remove_simple_function_name_comment(self):
        """Test removal of simple function name comments"""
        code = """/* TestFunc */
void TestFunc(void)
{
    return;
}"""
        cleaned = clean_decompiled_code(code)
        assert "/* TestFunc */" not in cleaned
        assert "void TestFunc" in cleaned

    def test_remove_blank_lines_inside_function(self):
        """Test removal of blank lines inside function body"""
        code = """void TestFunc(void)

{

  int x;

  int y;

  x = 1;

  y = 2;

  return;

}"""
        cleaned = clean_decompiled_code(code)
        lines = cleaned.split("\n")
        inside_braces = False
        blank_inside = 0
        for line in lines:
            if "{" in line:
                inside_braces = True
            if "}" in line:
                inside_braces = False
            if inside_braces and not line.strip():
                blank_inside += 1
        assert blank_inside == 0

    def test_preserve_blank_line_between_functions(self):
        """Test that one blank line is preserved between functions"""
        code = """void Func1(void)
{
    return;
}

void Func2(void)
{
    return;
}"""
        cleaned = clean_decompiled_code(code)
        assert "\n\nvoid Func2" in cleaned or "}\n\nvoid" in cleaned

    def test_collapse_multiple_blank_lines_outside_function(self):
        """Test that multiple blank lines outside functions are collapsed"""
        code = """void Func1(void)
{
    return;
}



void Func2(void)
{
    return;
}"""
        cleaned = clean_decompiled_code(code)
        assert "\n\n\n" not in cleaned

    def test_handle_empty_code(self):
        """Test handling of empty or None code"""
        assert clean_decompiled_code(None) is None
        assert clean_decompiled_code("") == ""

    def test_preserve_meaningful_comments(self):
        """Test that meaningful comments are preserved"""
        code = """/* This is a meaningful comment about the function */
void TestFunc(void)
{
    return;
}"""
        cleaned = clean_decompiled_code(code)
        assert "meaningful comment" in cleaned

    def test_nested_braces(self):
        """Test handling of nested braces"""
        code = """void TestFunc(void)
{

  if (x) {

    y = 1;

  }

  return;

}"""
        cleaned = clean_decompiled_code(code)
        assert "\n\n" not in cleaned.split("{", 1)[1].rsplit("}", 1)[0]

    def test_windows_line_endings(self):
        """Test handling of Windows CRLF line endings"""
        code = (
            "void TestFunc(void)\r\n\r\n{\r\n\r\n  int x;\r\n\r\n  return;\r\n\r\n}\r\n"
        )
        cleaned = clean_decompiled_code(code)
        assert "\r" not in cleaned

    def test_real_ghidra_output(self):
        """Test with real Ghidra-style output"""
        code = (
            "/* CMemStore::Alloc(unsigned int, unsigned char, unsigned char, "
            "unsigned char, unsigned char, unsigned char, unsigned int) */\n"
            "\n"
            "void * CMemStore::Alloc(uint param_1,undefined param_2,"
            "undefined param_3,undefined param_4,\n"
            "\n"
            "                       undefined param_5,undefined param_6,"
            "undefined4 param_7)\n"
            "\n"
            "\n"
            "\n"
            "{\n"
            "\n"
            "  void *pvVar1;\n"
            "\n"
            "  undefined4 in_register_0000003c;\n"
            "\n"
            "\n"
            "\n"
            "  pvVar1 = operator_new__(CONCAT44(in_register_0000003c,param_1));\n"
            "\n"
            "  return pvVar1;\n"
            "\n"
            "}"
        )
        cleaned = clean_decompiled_code(code)

        # Should remove the signature comment
        assert "/* CMemStore::Alloc" not in cleaned

        # Should remove blank lines inside function
        lines = cleaned.split("\n")
        # Count lines - should be much fewer
        assert len(lines) < len(code.split("\n"))

        # Function should still be valid
        assert "void * CMemStore::Alloc" in cleaned
        assert "return pvVar1;" in cleaned
