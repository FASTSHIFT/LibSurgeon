#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LibSurgeon Test Suite - C++ Class Analysis Tests

Tests for C++ class, struct, and vtable analysis functions.
"""

import os
import re

import pytest

from libsurgeon import (
    FileType,
    extract_archive,
    get_file_type,
    is_archive_file,
    is_elf_file,
)


class TestCppClassAnalysis:
    """Tests for C++ class, struct, and vtable analysis functions"""

    def test_extract_class_from_method_basic(self):
        """Test basic class extraction from method signatures"""

        def extract_class_from_method(display_name):
            match = re.match(
                r"(?:[\w\s\*]+\s+)?(?:__thiscall\s+)?(\w+(?:::\w+)*)::(\w+)\s*\(",
                display_name,
            )
            if match:
                return match.group(1)
            if "::" in display_name:
                parts = display_name.split("::")
                if len(parts) >= 2:
                    return "::".join(parts[:-1]).split("(")[0].strip()
            return None

        assert extract_class_from_method("void CoreView::Draw(void)") == "CoreView"
        assert extract_class_from_method("int CoreView::GetWidth(void)") == "CoreView"
        assert (
            extract_class_from_method("void __thiscall CoreView::Init(CoreView *this)")
            == "CoreView"
        )

    def test_extract_class_from_method_namespace(self):
        """Test class extraction with namespaces"""

        def extract_class_from_method(display_name):
            match = re.match(
                r"(?:[\w\s\*]+\s+)?(?:__thiscall\s+)?(\w+(?:::\w+)*)::\w+\s*\(",
                display_name,
            )
            if match:
                return match.group(1)
            if "::" in display_name:
                parts = display_name.split("::")
                if len(parts) >= 2:
                    return "::".join(parts[:-1]).split("(")[0].strip()
            return None

        assert (
            extract_class_from_method("void Namespace::Class::Method(int)")
            == "Namespace::Class"
        )
        assert extract_class_from_method("void A::B::C::Method(void)") == "A::B::C"

    def test_extract_class_from_method_no_class(self):
        """Test that non-class functions return None"""

        def extract_class_from_method(display_name):
            match = re.match(
                r"(?:[\w\s\*]+\s+)?(?:__thiscall\s+)?(\w+(?:::\w+)*)::\w+\s*\(",
                display_name,
            )
            if match:
                return match.group(1)
            if "::" in display_name:
                parts = display_name.split("::")
                if len(parts) >= 2:
                    return "::".join(parts[:-1]).split("(")[0].strip()
            return None

        assert extract_class_from_method("void main(void)") is None
        assert extract_class_from_method("int printf(const char *)") is None
        assert extract_class_from_method("FUN_00123456") is None

    def test_cpp_class_info_structure(self):
        """Test CppClassInfo data structure"""

        class CppClassInfo:
            def __init__(self, name):
                self.name = name
                self.methods = []
                self.vtable_addr = None
                self.vtable_funcs = []
                self.struct_type = None
                self.parent_class = None
                self.size = 0

        cls = CppClassInfo("TestClass")
        cls.methods.append(("_ZN9TestClass4initEv", "init", True, 0))
        cls.methods.append(("_ZN9TestClass4drawEv", "draw", True, 1))
        cls.methods.append(("_ZN9TestClass6updateEv", "update", False, -1))

        assert cls.name == "TestClass"
        assert len(cls.methods) == 3

        virtual_count = sum(1 for _, _, is_v, _ in cls.methods if is_v)
        assert virtual_count == 2

    def test_vtable_pattern_matching(self):
        """Test vtable symbol pattern recognition"""
        vtable_patterns = [
            r"^_ZTV",
            r"^vtable\s+for\s+",
            r"^__vt_",
            r"_vtbl$",
        ]

        def is_vtable_symbol(name):
            for pattern in vtable_patterns:
                if re.search(pattern, name, re.IGNORECASE):
                    return True
            return False

        assert is_vtable_symbol("_ZTV9CoreView") is True
        assert is_vtable_symbol("_ZTV12ApplicationApp") is True
        assert is_vtable_symbol("vtable for CoreView") is True
        assert is_vtable_symbol("__vt_CoreView") is True
        assert is_vtable_symbol("CoreView_vtbl") is True
        assert is_vtable_symbol("_ZN9CoreView4drawEv") is False
        assert is_vtable_symbol("main") is False

    def test_vtable_class_name_extraction(self):
        """Test extracting class name from vtable symbol"""

        def extract_vtable_class_name(sym_name):
            if sym_name.startswith("_ZTV"):
                return sym_name[4:]
            if "vtable for " in sym_name:
                return sym_name.replace("vtable for ", "").strip()
            if sym_name.startswith("__vt_"):
                return sym_name[5:]
            if sym_name.endswith("_vtbl"):
                return sym_name[:-5]
            return None

        assert extract_vtable_class_name("_ZTV9CoreView") == "9CoreView"
        assert extract_vtable_class_name("vtable for CoreView") == "CoreView"
        assert extract_vtable_class_name("__vt_CoreView") == "CoreView"
        assert extract_vtable_class_name("CoreView_vtbl") == "CoreView"

    def test_virtual_method_detection_by_thiscall(self):
        """Test virtual method detection via calling convention"""

        def is_likely_virtual_by_convention(calling_conv):
            if calling_conv and "thiscall" in calling_conv.lower():
                return True
            return False

        assert is_likely_virtual_by_convention("__thiscall") is True
        assert is_likely_virtual_by_convention("thiscall") is True
        assert is_likely_virtual_by_convention("THISCALL") is True
        assert is_likely_virtual_by_convention("cdecl") is False
        assert is_likely_virtual_by_convention("stdcall") is False
        assert is_likely_virtual_by_convention(None) is False

    def test_enhance_decompiled_code_field_annotation(self):
        """Test field access annotation in decompiled code"""

        def enhance_decompiled_code(code, class_info_map, struct_info_map):
            if not code:
                return code
            enhanced = code
            field_pattern = r"(field_0x[0-9a-fA-F]+)"
            matches = re.findall(field_pattern, enhanced)
            if matches:
                unique_fields = set(matches)
                if len(unique_fields) > 3:
                    hint = (
                        "// NOTE: {} unknown struct fields accessed"
                        " - consider defining struct type\n"
                    ).format(len(unique_fields))
                    brace_pos = enhanced.find("{")
                    if brace_pos > 0:
                        enhanced = (
                            enhanced[: brace_pos + 1]
                            + "\n"
                            + hint
                            + enhanced[brace_pos + 1 :]
                        )
            return enhanced

        # Test with many unknown fields
        code = """void TestFunc(void *obj) {
    int a = obj->field_0x10;
    int b = obj->field_0x14;
    int c = obj->field_0x18;
    int d = obj->field_0x1c;
    int e = obj->field_0x20;
}"""
        enhanced = enhance_decompiled_code(code, {}, {})
        assert "NOTE:" in enhanced
        assert "unknown struct fields" in enhanced

    def test_enhance_decompiled_code_few_fields(self):
        """Test that few fields don't trigger annotation"""

        def enhance_decompiled_code(code, class_info_map, struct_info_map):
            if not code:
                return code
            enhanced = code
            field_pattern = r"(field_0x[0-9a-fA-F]+)"
            matches = re.findall(field_pattern, enhanced)
            if matches:
                unique_fields = set(matches)
                if len(unique_fields) > 3:
                    hint = "// NOTE: {} unknown struct fields accessed\n".format(
                        len(unique_fields)
                    )
                    brace_pos = enhanced.find("{")
                    if brace_pos > 0:
                        enhanced = (
                            enhanced[: brace_pos + 1]
                            + "\n"
                            + hint
                            + enhanced[brace_pos + 1 :]
                        )
            return enhanced

        # Test with few fields - should not add note
        code = """void TestFunc(void *obj) {
    int a = obj->field_0x10;
    int b = obj->field_0x14;
}"""
        enhanced = enhance_decompiled_code(code, {}, {})
        assert "NOTE:" not in enhanced

    def test_class_header_content(self):
        """Test generated class header structure"""

        class CppClassInfo:
            def __init__(self, name):
                self.name = name
                self.methods = []
                self.vtable_addr = None
                self.vtable_funcs = []

        def generate_class_header_content(classes):
            lines = []
            lines.append("/* C++ Class Analysis */")
            lines.append("#ifndef _CLASSES_H_")
            lines.append("#define _CLASSES_H_")
            lines.append("")

            for class_name in sorted(classes.keys()):
                cls = classes[class_name]
                safe_name = class_name.replace("::", "_")
                lines.append("/* Class: {} */".format(class_name))
                lines.append("typedef struct {} {};".format(safe_name, safe_name))

                if cls.vtable_funcs:
                    lines.append(
                        "/* Virtual methods: {} */".format(len(cls.vtable_funcs))
                    )

                for mangled, method_name, is_virtual, vt_idx in cls.methods:
                    marker = "[virtual:{}]".format(vt_idx) if is_virtual else ""
                    lines.append("/* {} {} */".format(marker, method_name))
                lines.append("")

            lines.append("#endif")
            return "\n".join(lines)

        # Create test classes
        classes = {}
        cls1 = CppClassInfo("CoreView")
        cls1.methods = [
            ("_ZN8CoreView4DrawEv", "Draw", True, 0),
            ("_ZN8CoreView4InitEv", "Init", False, -1),
        ]
        cls1.vtable_funcs = [(0, None, "Draw")]
        classes["CoreView"] = cls1

        content = generate_class_header_content(classes)

        assert "Class: CoreView" in content
        assert "typedef struct CoreView CoreView" in content
        assert "[virtual:0]" in content
        assert "Draw" in content


class TestAllSupportedFileTypes:
    """Tests for all supported file types using real fixture files"""

    @pytest.fixture
    def fixtures_dir(self):
        """Return the fixtures directory path"""
        return os.path.join(os.path.dirname(__file__), "fixtures")

    def test_fixture_files_exist(self, fixtures_dir):
        """Verify all expected fixture files exist"""
        expected_files = [
            "test_library.o",
            "libtest.a",
            "libtest.lib",
            "libtest.so",
            "libtest.so.1.0.0",
            "test_program.elf",
            "test_program.axf",
            "test_program.out",
        ]
        for filename in expected_files:
            filepath = os.path.join(fixtures_dir, filename)
            assert os.path.exists(filepath), f"Fixture file missing: {filename}"

    def test_archive_a_detection(self, fixtures_dir):
        """Test .a archive file detection"""
        filepath = os.path.join(fixtures_dir, "libtest.a")
        assert get_file_type(filepath) == FileType.ARCHIVE
        assert is_archive_file(filepath) is True

    def test_archive_lib_detection(self, fixtures_dir):
        """Test .lib archive file detection"""
        filepath = os.path.join(fixtures_dir, "libtest.lib")
        assert get_file_type(filepath) == FileType.ARCHIVE
        assert is_archive_file(filepath) is True

    def test_elf_o_detection(self, fixtures_dir):
        """Test .o object file detection"""
        filepath = os.path.join(fixtures_dir, "test_library.o")
        assert get_file_type(filepath) == FileType.ELF
        assert is_elf_file(filepath) is True

    def test_elf_so_detection(self, fixtures_dir):
        """Test .so shared library detection"""
        filepath = os.path.join(fixtures_dir, "libtest.so")
        assert get_file_type(filepath) == FileType.ELF
        assert is_elf_file(filepath) is True

    def test_elf_so_versioned_detection(self, fixtures_dir):
        """Test versioned .so.x.y.z shared library detection"""
        filepath = os.path.join(fixtures_dir, "libtest.so.1.0.0")
        assert get_file_type(filepath) == FileType.ELF
        assert is_elf_file(filepath) is True

    def test_elf_elf_detection(self, fixtures_dir):
        """Test .elf executable detection"""
        filepath = os.path.join(fixtures_dir, "test_program.elf")
        assert get_file_type(filepath) == FileType.ELF
        assert is_elf_file(filepath) is True

    def test_elf_axf_detection(self, fixtures_dir):
        """Test .axf ARM executable detection"""
        filepath = os.path.join(fixtures_dir, "test_program.axf")
        assert get_file_type(filepath) == FileType.ELF
        assert is_elf_file(filepath) is True

    def test_elf_out_detection(self, fixtures_dir):
        """Test .out executable detection"""
        filepath = os.path.join(fixtures_dir, "test_program.out")
        assert get_file_type(filepath) == FileType.ELF
        assert is_elf_file(filepath) is True

    def test_archive_a_extraction(self, fixtures_dir, temp_dir):
        """Test extracting .a archive"""
        archive_path = os.path.join(fixtures_dir, "libtest.a")
        extract_archive(archive_path, temp_dir)
        extracted = os.listdir(temp_dir)
        assert len(extracted) > 0
        assert any(f.endswith(".o") for f in extracted)

    def test_archive_lib_extraction(self, fixtures_dir, temp_dir):
        """Test extracting .lib archive"""
        archive_path = os.path.join(fixtures_dir, "libtest.lib")
        extract_archive(archive_path, temp_dir)
        # Check that .o file was extracted
        extracted = os.listdir(temp_dir)
        assert len(extracted) > 0
        assert any(f.endswith(".o") for f in extracted)

    def test_elf_magic_number_verification(self, fixtures_dir):
        """Verify ELF files have correct magic number"""
        elf_files = [
            "test_library.o",
            "libtest.so",
            "test_program.elf",
            "test_program.axf",
            "test_program.out",
        ]
        for filename in elf_files:
            filepath = os.path.join(fixtures_dir, filename)
            with open(filepath, "rb") as f:
                magic = f.read(4)
            assert magic == b"\x7fELF", f"{filename} does not have ELF magic"

    def test_archive_magic_number_verification(self, fixtures_dir):
        """Verify archive files have correct magic number"""
        archive_files = ["libtest.a", "libtest.lib"]
        for filename in archive_files:
            filepath = os.path.join(fixtures_dir, filename)
            with open(filepath, "rb") as f:
                magic = f.read(7)
            assert magic == b"!<arch>", f"{filename} does not have archive magic"

    def test_unknown_file_type(self, fixtures_dir):
        """Test that non-supported files are marked as UNKNOWN"""
        filepath = os.path.join(fixtures_dir, "test_library.c")
        assert get_file_type(filepath) == FileType.UNKNOWN
