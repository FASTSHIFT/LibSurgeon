#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LibSurgeon - Ghidra Common Utilities

Shared utilities for Ghidra decompilation scripts.
This module contains common functions used by both ghidra_decompile_lib.py
(for .a/.o files) and ghidra_decompile_elf.py (for ELF files).

Note: This module runs in Ghidra's Jython environment and uses Ghidra's API.
"""

import os
import re

# Ghidra undefined type to standard C type mapping
# For 'undefined' types, we use custom typedefs (unk8_t, unk16_t, etc.)
# since Ghidra cannot determine signedness. Users can adjust as needed.
GHIDRA_TYPE_MAP = {
    # Undefined types - use custom 'unk' types to indicate uncertainty
    # These will be typedef'd in _types.h, defaulting to signed
    "undefined": "unk8_t",
    "undefined1": "unk8_t",
    "undefined2": "unk16_t",
    "undefined3": "unk32_t",  # 3 bytes, approximate with 32-bit
    "undefined4": "unk32_t",
    "undefined5": "unk64_t",
    "undefined6": "unk64_t",
    "undefined7": "unk64_t",
    "undefined8": "unk64_t",
    # Basic types - these have known signedness
    "byte": "uint8_t",
    "ubyte": "uint8_t",
    "sbyte": "int8_t",
    "word": "uint16_t",
    "sword": "int16_t",
    "dword": "uint32_t",
    "sdword": "int32_t",
    "qword": "uint64_t",
    "sqword": "int64_t",
    # Ghidra specific - usually unsigned
    "uint": "uint32_t",
    "ushort": "uint16_t",
    "ulong": "uint32_t",
    "ulonglong": "uint64_t",
    "longlong": "int64_t",
    "uchar": "uint8_t",
    "schar": "int8_t",
    # Pointer placeholders
    "addr": "void *",
    "pointer": "void *",
}

# Unknown type definitions - these go into _types.h
# Default to signed types (more common in embedded code)
UNKNOWN_TYPE_DEFS = """
/**
 * Unknown/Undefined Types
 * 
 * These types represent data where Ghidra could not determine signedness.
 * Adjust to uint*_t if unsigned behavior is observed.
 * 
 * Common patterns:
 *   - Loop counters, array indices -> usually signed (int)
 *   - Bit manipulation, masks -> usually unsigned (uint)
 *   - Memory addresses, sizes -> usually unsigned (uint)
 *   - Return codes, status -> usually signed (int)
 */
typedef int8_t   unk8_t;    /* undefined1 - could be int8_t or uint8_t */
typedef int16_t  unk16_t;   /* undefined2 - could be int16_t or uint16_t */
typedef int32_t  unk32_t;   /* undefined4 - could be int32_t or uint32_t */
typedef int64_t  unk64_t;   /* undefined8 - could be int64_t or uint64_t */

/* Pointer-sized unknown type */
typedef intptr_t unkptr_t;  /* undefined pointer-sized value */
"""


# ============================================================
# Type Normalization Functions
# ============================================================


def normalize_ghidra_type(type_str):
    """Convert Ghidra-specific types to standard C types"""
    if not type_str:
        return type_str

    # Handle pointer types first
    ptr_count = type_str.count("*")
    base_type = type_str.replace("*", "").strip()

    # Check if it's a mapped type
    if base_type in GHIDRA_TYPE_MAP:
        base_type = GHIDRA_TYPE_MAP[base_type]

    # Reconstruct with pointers
    if ptr_count > 0:
        return base_type + " " + "*" * ptr_count

    return base_type


def normalize_code_types(code):
    """Replace Ghidra-specific types with standard C types in decompiled code"""
    if not code:
        return code

    # Apply type mappings using word boundaries
    for ghidra_type, c_type in GHIDRA_TYPE_MAP.items():
        # Use word boundary to avoid partial replacements
        pattern = r"\b" + re.escape(ghidra_type) + r"\b"
        code = re.sub(pattern, c_type, code)

    return code


# ============================================================
# Name Processing Functions
# ============================================================


def demangle_cpp_name(mangled_name, program):
    """
    Attempt to demangle C++ mangled names.

    Args:
        mangled_name: The mangled C++ name (e.g., _ZN8ClassNam4funcEv)
        program: The Ghidra program object (currentProgram)

    Returns:
        Demangled name or original if demangling fails
    """
    try:
        from ghidra.app.util.demangler import DemanglerUtil

        demangled = DemanglerUtil.demangle(program, mangled_name)
        if demangled:
            return demangled.getSignature(False)
    except:
        pass
    return mangled_name


def sanitize_filename(name):
    """
    Sanitize filename by removing illegal characters.

    Args:
        name: Original filename

    Returns:
        Sanitized filename safe for filesystem use
    """
    name = re.sub(r'[<>:"/\\|?*]', "_", name)
    name = re.sub(r"\s+", "_", name)
    name = re.sub(r"[^\w\-]", "_", name)
    # Collapse multiple underscores
    name = re.sub(r"_+", "_", name)
    name = name.strip("_")
    if len(name) > 100:
        name = name[:100]
    return name


def extract_class_name(func_name):
    """
    Extract class name from function name.

    Args:
        func_name: Function name (possibly with namespace::class::method format)

    Returns:
        Class name or None if not found
    """
    if "::" in func_name:
        parts = func_name.split("::")
        if len(parts) >= 2:
            return parts[-2] if len(parts) > 2 else parts[0]
    return None


def extract_namespace(func_name):
    """
    Extract top-level namespace from function name.

    Args:
        func_name: Function name (possibly with namespace::class::method format)

    Returns:
        Namespace or None if not found
    """
    if "::" in func_name:
        parts = func_name.split("::")
        if len(parts) >= 1:
            return parts[0]
    return None


def extract_class_from_method(display_name):
    """
    Extract class name from a method signature.

    Examples:
        'void CoreView::Draw(void)' -> 'CoreView'
        'void Namespace::Class::Method(int)' -> 'Namespace::Class'
        'void __thiscall CoreView::Init(CoreView *this)' -> 'CoreView'

    Args:
        display_name: The display name/signature of the method

    Returns:
        Class name or None if not a method
    """
    # Remove return type prefix
    match = re.match(
        r"(?:[\w\s\*]+\s+)?(?:__thiscall\s+)?(\w+(?:::\w+)*)::\w+\s*\(", display_name
    )
    if match:
        return match.group(1)

    # Try simpler pattern for mangled names
    if "::" in display_name:
        parts = display_name.split("::")
        if len(parts) >= 2:
            # Return everything except the last part (method name)
            return "::".join(parts[:-1]).split("(")[0].strip()

    return None


# ============================================================
# Function Filtering
# ============================================================

# Patterns for functions to skip during decompilation
SKIP_FUNCTION_PATTERNS = [
    "__stack_chk_fail",
    "__assert_fail",
    "__cxa_",
    "__gxx_",
    "operator delete",
    "operator new",
    "_Unwind_",
    "__cxx_global_",
    "_GLOBAL__",
    "__static_initialization",
]


def should_skip_function(func, program):
    """
    Determine if a function should be skipped during decompilation.

    Skips:
    - External symbols (libc, libstdc++, etc.)
    - Thunk functions (jump stubs)
    - Functions in EXTERNAL memory block
    - Common library function patterns

    Args:
        func: Ghidra Function object
        program: Ghidra Program object (currentProgram)

    Returns:
        True if function should be skipped
    """
    func_name = func.getName()

    # Skip functions in EXTERNAL block (libc, libstdc++, etc.)
    if func.isExternal():
        return True

    # Skip thunk functions (jump stubs)
    if func.isThunk():
        return True

    # Skip functions with addresses in EXTERNAL memory block
    addr = func.getEntryPoint()
    mem = program.getMemory()
    block = mem.getBlock(addr)
    if block is not None:
        block_name = block.getName()
        # Skip EXTERNAL and .group.* sections
        if block_name == "EXTERNAL" or block_name.startswith(".group"):
            return True

    # Skip common libc/libstdc++ external function names
    for pattern in SKIP_FUNCTION_PATTERNS:
        if pattern in func_name:
            return True

    return False


# ============================================================
# Decompilation Functions
# ============================================================


def clean_decompiled_code(code):
    """
    Clean up decompiled code by removing unnecessary comments and blank lines.

    Removes:
    - Function signature comments like /* FuncName(args) */
    - Excessive blank lines (keep max 1 between statements, none inside blocks)

    Args:
        code: Raw decompiled C code

    Returns:
        Cleaned up code
    """
    if not code:
        return code

    lines = code.split("\n")
    cleaned_lines = []
    prev_blank = False
    inside_function = False
    brace_depth = 0

    for line in lines:
        stripped = line.strip()

        # Skip function signature comments: /* FuncName(...) */ or /* FuncName */
        # These appear at the start of functions and are redundant
        if stripped.startswith("/*") and stripped.endswith("*/"):
            # Check if it looks like a function signature comment
            inner = stripped[2:-2].strip()
            # Skip if it contains parentheses (function signature) or is just a name
            if "(" in inner or (inner and " " not in inner and len(inner) < 100):
                continue

        # Track brace depth to know if we're inside a function body
        brace_depth += stripped.count("{") - stripped.count("}")
        inside_function = brace_depth > 0

        # Handle blank lines
        if not stripped:
            # Inside function body: skip all blank lines for compact code
            if inside_function:
                continue
            # Outside function: keep max 1 consecutive blank line
            if prev_blank:
                continue
            prev_blank = True
        else:
            prev_blank = False

        cleaned_lines.append(line)

    # Remove trailing blank lines
    while cleaned_lines and not cleaned_lines[-1].strip():
        cleaned_lines.pop()

    return "\n".join(cleaned_lines)


def get_decompiled_function_basic(decomp_ifc, func, monitor):
    """
    Decompile a single function and return C code.

    Basic version without type normalization or enhancements.

    Args:
        decomp_ifc: Ghidra DecompInterface
        func: Ghidra Function object
        monitor: Task monitor

    Returns:
        Decompiled C code string or None on failure
    """
    try:
        results = decomp_ifc.decompileFunction(func, 60, monitor)
        if results and results.decompileCompleted():
            code = results.getDecompiledFunction().getC()
            return clean_decompiled_code(code)
    except Exception as e:
        print("  [Error] Failed to decompile {}: {}".format(func.getName(), str(e)))
    return None


def get_decompiled_function(
    decomp_ifc, func, monitor, class_info=None, struct_info=None, enhance=True
):
    """
    Decompile a single function and return C code with normalized types.

    Enhanced version with type normalization and optional code enhancement.

    Args:
        decomp_ifc: Ghidra DecompInterface
        func: Ghidra Function object
        monitor: Task monitor
        class_info: Optional dict of class information for enhancement
        struct_info: Optional dict of struct information for enhancement
        enhance: Whether to apply code enhancement (default True)

    Returns:
        Decompiled C code string or None on failure
    """
    try:
        results = decomp_ifc.decompileFunction(func, 60, monitor)
        if results and results.decompileCompleted():
            code = results.getDecompiledFunction().getC()
            # Normalize Ghidra-specific types to standard C types
            code = normalize_code_types(code)
            # Optionally enhance with class/struct analysis
            if enhance and (class_info or struct_info):
                code = enhance_decompiled_code(
                    code, class_info or {}, struct_info or {}
                )
            return code
    except Exception as e:
        print("  [Error] Failed to decompile {}: {}".format(func.getName(), str(e)))
    return None


def enhance_decompiled_code(code, class_info_map, struct_info_map):
    """
    Enhance decompiled code with class/struct field annotations.

    Improvements:
    1. Annotate this->field_0x10 with struct member info if known
    2. Mark virtual function calls
    3. Add class hierarchy comments

    Args:
        code: Decompiled C code
        class_info_map: Dict of class name -> CppClassInfo
        struct_info_map: Dict of struct name -> struct definition

    Returns:
        Enhanced code with annotations
    """
    if not code:
        return code

    enhanced = code

    # Pattern to match struct field access: *(type *)(ptr + offset)
    # or: ptr->field_0xNN
    field_pattern = r"(field_0x[0-9a-fA-F]+)"

    # Add comments for unknown fields to help analysis
    matches = re.findall(field_pattern, enhanced)
    if matches:
        # Add a hint comment at the function start if there are many unknown fields
        unique_fields = set(matches)
        if len(unique_fields) > 3:
            hint = (
                "// NOTE: {} unknown struct fields accessed "
                "- consider defining struct type\n".format(len(unique_fields))
            )
            # Insert after function signature
            brace_pos = enhanced.find("{")
            if brace_pos > 0:
                enhanced = (
                    enhanced[: brace_pos + 1] + "\n" + hint + enhanced[brace_pos + 1 :]
                )

    # Pattern to match vtable calls: (*(func_ptr_type *)(*obj + offset))()
    vtable_pattern = r"\(\*\*\(\w+\s*\*\*\)\(\*?\(?(\w+)\)?\s*\+\s*(0x[0-9a-fA-F]+)\)\)"

    def vtable_replacer(match):
        offset = match.group(2)
        # Add annotation comment
        return match.group(0) + " /* vtable[{}] */".format(offset)

    enhanced = re.sub(vtable_pattern, vtable_replacer, enhanced)

    return enhanced


# ============================================================
# File Header Generation
# ============================================================


def write_file_header(f, module_name, func_count, program_name=None):
    """
    Write a standard file header for decompiled source files.

    Args:
        f: File object to write to
        module_name: Name of the module
        func_count: Number of functions in the module
        program_name: Optional source program name
    """
    f.write("/**\n")
    f.write(" * Module: {}\n".format(module_name))
    if program_name:
        f.write(" * Source: {}\n".format(program_name))
    f.write(" * Functions: {}\n".format(func_count))
    f.write(" *\n")
    f.write(" * Auto-generated by LibSurgeon (Ghidra-based decompiler)\n")
    f.write(" *\n")
    f.write(
        " * WARNING: This is automatically generated code from reverse engineering.\n"
    )
    f.write(" * It may not compile directly and is intended for analysis purposes.\n")
    f.write(" */\n\n")
    f.write("#include <stdint.h>\n")
    f.write("#include <stdbool.h>\n")
    f.write("#include <stddef.h>\n\n")


# ============================================================
# Header File Generation Functions
# ============================================================


def extract_function_signature(decompiled_code):
    """
    Extract function signature from decompiled code.
    Returns the normalized function signature string or None if extraction fails.
    """
    if not decompiled_code:
        return None

    # Find the first function definition (before the opening brace)
    lines = decompiled_code.strip().split("\n")
    signature_lines = []

    for line in lines:
        if "{" in line:
            # Include part before the brace
            signature_lines.append(line.split("{")[0].strip())
            break
        signature_lines.append(line.strip())

    if not signature_lines:
        return None

    signature = " ".join(signature_lines).strip()

    # Clean up the signature
    signature = re.sub(r"\s+", " ", signature)

    # Skip if it looks like a variable declaration or empty
    if not signature or signature.endswith(";"):
        return None

    # Normalize types in the signature
    signature = normalize_code_types(signature)

    return signature


def generate_header_file(
    output_dir, module_name, func_signatures, source_type="decompilation"
):
    """
    Generate a header file for a module with function declarations.

    Args:
        output_dir: Directory to write the header file
        module_name: Name of the module
        func_signatures: List of (func_name, signature) tuples
        source_type: Description of the source (e.g., "ELF decompilation", "library decompilation")

    Returns:
        Path to the generated header file
    """
    safe_name = sanitize_filename(module_name)
    header_file = os.path.join(output_dir, "{}.h".format(safe_name))

    guard_name = "_{}_H_".format(safe_name.upper())

    with open(header_file, "w") as f:
        f.write("/**\n")
        f.write(" * Header: {}.h\n".format(safe_name))
        f.write(" * Module: {}\n".format(module_name))
        f.write(" * Functions: {}\n".format(len(func_signatures)))
        f.write(" * \n")
        f.write(" * Auto-generated by LibSurgeon from {}\n".format(source_type))
        f.write(" */\n\n")

        f.write("#ifndef {}\n".format(guard_name))
        f.write("#define {}\n\n".format(guard_name))

        f.write("#include <stdint.h>\n")
        f.write("#include <stdbool.h>\n")
        f.write("#include <stddef.h>\n")
        f.write('#include "_types.h"\n\n')

        f.write("#ifdef __cplusplus\n")
        f.write('extern "C" {\n')
        f.write("#endif\n\n")

        # Write function declarations
        f.write("/* Function Declarations */\n\n")
        for func_name, signature in sorted(func_signatures, key=lambda x: x[0]):
            if signature:
                f.write("/* {} */\n".format(func_name))
                f.write("{};\n\n".format(signature))

        f.write("#ifdef __cplusplus\n")
        f.write("}\n")
        f.write("#endif\n\n")

        f.write("#endif /* {} */\n".format(guard_name))

    return header_file


def generate_master_header(output_dir, module_names, program_name):
    """
    Generate a master header file that includes all module headers.

    Args:
        output_dir: Directory to write the header file
        module_names: Iterable of module names
        program_name: Name of the source program

    Returns:
        Path to the generated master header file
    """
    header_file = os.path.join(output_dir, "_all_headers.h")

    with open(header_file, "w") as f:
        f.write("/**\n")
        f.write(" * Master Header File\n")
        f.write(" * Source: {}\n".format(program_name))
        f.write(" * Modules: {}\n".format(len(list(module_names))))
        f.write(" * \n")
        f.write(" * Auto-generated by LibSurgeon\n")
        f.write(" * Include this file to get all function declarations.\n")
        f.write(" */\n\n")

        f.write("#ifndef _ALL_HEADERS_H_\n")
        f.write("#define _ALL_HEADERS_H_\n\n")

        f.write('#include "_types.h"\n\n')

        for module_name in sorted(module_names):
            safe_name = sanitize_filename(module_name)
            f.write('#include "{}.h"\n'.format(safe_name))

        f.write("\n#endif /* _ALL_HEADERS_H_ */\n")

    return header_file


def generate_types_header(output_dir):
    """
    Generate _types.h header with type definitions.

    Args:
        output_dir: Directory to write the header file

    Returns:
        Path to the generated types header file
    """
    types_file = os.path.join(output_dir, "_types.h")

    with open(types_file, "w") as f:
        f.write("/**\n")
        f.write(" * Type Definitions for Decompiled Code\n")
        f.write(" * \n")
        f.write(" * This file contains typedef mappings for Ghidra-generated types.\n")
        f.write(" * Auto-generated by LibSurgeon\n")
        f.write(" */\n\n")

        f.write("#ifndef _LIBSURGEON_TYPES_H_\n")
        f.write("#define _LIBSURGEON_TYPES_H_\n\n")

        f.write("#include <stdint.h>\n")
        f.write("#include <stdbool.h>\n\n")

        f.write("/* Unknown type definitions (signedness uncertain) */\n")
        f.write(UNKNOWN_TYPE_DEFS)
        f.write("\n")

        f.write("#endif /* _LIBSURGEON_TYPES_H_ */\n")

    return types_file
