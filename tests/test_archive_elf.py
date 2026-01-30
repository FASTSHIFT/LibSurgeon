#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LibSurgeon Test Suite - Archive and ELF Processing Tests

Tests for archive extraction and ELF file detection/architecture detection.
"""

import os

import pytest  # noqa: F401 - used by fixtures

from libsurgeon import (
    ELF_MACHINE_MAP,
    detect_elf_architecture,
    extract_archive,
    is_archive_file,
    is_elf_file,
)


class TestArchiveProcessing:
    """Tests for archive processing"""

    def test_extract_archive(self, test_archive, temp_dir):
        """Test archive extraction"""
        extract_dir = os.path.join(temp_dir, "extracted")
        obj_files = extract_archive(test_archive, extract_dir)

        assert len(obj_files) >= 1
        assert any(f.endswith(".o") for f in obj_files)

    def test_extract_archive_relative_path(self, test_archive, temp_dir):
        """Test archive extraction with relative path"""
        orig_dir = os.getcwd()
        try:
            parent_dir = os.path.dirname(test_archive)
            archive_name = os.path.basename(test_archive)
            os.chdir(parent_dir)

            extract_dir = os.path.join(temp_dir, "extracted_rel")
            obj_files = extract_archive(archive_name, extract_dir)

            assert len(obj_files) >= 1
            assert any(f.endswith(".o") for f in obj_files)
        finally:
            os.chdir(orig_dir)

    def test_is_archive_file(self, test_archive, temp_dir):
        """Test archive magic number detection"""
        assert is_archive_file(test_archive) is True

        fake_file = os.path.join(temp_dir, "fake.a")
        with open(fake_file, "w") as f:
            f.write("not an archive")
        assert is_archive_file(fake_file) is False


class TestElfDetection:
    """Tests for ELF file detection"""

    def test_is_elf_file_valid(self, temp_dir):
        """Test valid ELF magic number detection"""
        elf_file = os.path.join(temp_dir, "test.elf")
        with open(elf_file, "wb") as f:
            f.write(b"\x7fELF")
            f.write(b"\x00" * 100)
        assert is_elf_file(elf_file) is True

    def test_is_elf_file_invalid(self, temp_dir):
        """Test non-ELF file detection"""
        non_elf = os.path.join(temp_dir, "not_elf.bin")
        with open(non_elf, "wb") as f:
            f.write(b"NOT_ELF_CONTENT")
        assert is_elf_file(non_elf) is False

    def test_is_elf_file_too_small(self, temp_dir):
        """Test file too small for ELF header"""
        small_file = os.path.join(temp_dir, "small.elf")
        with open(small_file, "wb") as f:
            f.write(b"\x7fE")
        assert is_elf_file(small_file) is False

    def test_is_elf_file_nonexistent(self):
        """Test nonexistent file"""
        assert is_elf_file("/nonexistent/path/file.elf") is False


class TestElfArchitectureDetection:
    """Tests for ELF architecture detection"""

    def test_detect_arm32_little_endian(self, temp_dir):
        """Test ARM 32-bit little endian detection"""
        elf_file = os.path.join(temp_dir, "arm32le.o")
        with open(elf_file, "wb") as f:
            f.write(b"\x7fELF")
            f.write(b"\x01")  # 32-bit
            f.write(b"\x01")  # little endian
            f.write(b"\x01\x00\x00" + b"\x00" * 7)
            f.write(b"\x01\x00")
            f.write(b"\x28\x00")  # ARM
            f.write(b"\x00" * 100)

        result = detect_elf_architecture(elf_file)
        assert result is not None
        processor, cspec = result
        assert "ARM" in processor
        assert "LE" in processor
        assert "32" in processor

    def test_detect_arm64_little_endian(self, temp_dir):
        """Test ARM 64-bit (AARCH64) detection"""
        elf_file = os.path.join(temp_dir, "arm64le.o")
        with open(elf_file, "wb") as f:
            f.write(b"\x7fELF")
            f.write(b"\x02")  # 64-bit
            f.write(b"\x01")  # little endian
            f.write(b"\x01\x00\x00" + b"\x00" * 7)
            f.write(b"\x01\x00")
            f.write(b"\xb7\x00")  # AARCH64
            f.write(b"\x00" * 100)

        result = detect_elf_architecture(elf_file)
        assert result is not None
        processor, cspec = result
        assert "AARCH64" in processor
        assert "LE" in processor
        assert "64" in processor

    def test_detect_x86_32(self, temp_dir):
        """Test x86 32-bit detection"""
        elf_file = os.path.join(temp_dir, "x86_32.o")
        with open(elf_file, "wb") as f:
            f.write(b"\x7fELF")
            f.write(b"\x01")
            f.write(b"\x01")
            f.write(b"\x01\x00\x00" + b"\x00" * 7)
            f.write(b"\x01\x00")
            f.write(b"\x03\x00")  # x86
            f.write(b"\x00" * 100)

        result = detect_elf_architecture(elf_file)
        assert result is not None
        processor, cspec = result
        assert "x86" in processor
        assert "32" in processor

    def test_detect_x86_64(self, temp_dir):
        """Test x86-64 detection"""
        elf_file = os.path.join(temp_dir, "x86_64.o")
        with open(elf_file, "wb") as f:
            f.write(b"\x7fELF")
            f.write(b"\x02")
            f.write(b"\x01")
            f.write(b"\x01\x00\x00" + b"\x00" * 7)
            f.write(b"\x01\x00")
            f.write(b"\x3e\x00")  # x86-64
            f.write(b"\x00" * 100)

        result = detect_elf_architecture(elf_file)
        assert result is not None
        processor, cspec = result
        assert "x86" in processor
        assert "64" in processor

    def test_detect_riscv32(self, temp_dir):
        """Test RISC-V 32-bit detection"""
        elf_file = os.path.join(temp_dir, "riscv32.o")
        with open(elf_file, "wb") as f:
            f.write(b"\x7fELF")
            f.write(b"\x01")
            f.write(b"\x01")
            f.write(b"\x01\x00\x00" + b"\x00" * 7)
            f.write(b"\x01\x00")
            f.write(b"\xf3\x00")  # RISC-V
            f.write(b"\x00" * 100)

        result = detect_elf_architecture(elf_file)
        assert result is not None
        processor, cspec = result
        assert "RISCV" in processor
        assert "32" in processor

    def test_detect_nonexistent_file(self):
        """Test detection on nonexistent file"""
        result = detect_elf_architecture("/nonexistent/path/file.o")
        assert result is None

    def test_detect_non_elf_file(self, temp_dir):
        """Test detection on non-ELF file"""
        non_elf = os.path.join(temp_dir, "not_elf.bin")
        with open(non_elf, "wb") as f:
            f.write(b"NOT_ELF_CONTENT")
        result = detect_elf_architecture(non_elf)
        assert result is None

    def test_elf_machine_map_exists(self):
        """Test that ELF machine map has expected entries"""
        assert 0x03 in ELF_MACHINE_MAP  # x86
        assert 0x3E in ELF_MACHINE_MAP  # x86-64
        assert 0x28 in ELF_MACHINE_MAP  # ARM
        assert 0xB7 in ELF_MACHINE_MAP  # AARCH64
        assert 0xF3 in ELF_MACHINE_MAP  # RISC-V
