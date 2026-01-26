#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LibSurgeon - Ghidra Headless Decompilation Script for ELF Files

This script runs in Ghidra's Headless mode to automatically analyze
and decompile ELF files with intelligent module grouping.

Features:
  - Module grouping by function name prefix
  - C++ class/struct analysis
  - Virtual function table (vtable) parsing
  - Improved struct field access annotation

Module Grouping Strategies:
  - prefix: Group by function name prefix (e.g., xxBmp*, xxFnt*)
  - alpha: Group by first letter (A-Z)
  - camelcase: Extract CamelCase words as module names
  - single: All functions in one file

For library (.a/.o) file processing, use ghidra_decompile_lib.py instead.
"""

import os
import re
import sys
from collections import OrderedDict, defaultdict

# Add the script's directory to Python path for importing ghidra_common
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

# Ghidra Python scripts use Jython with Ghidra's API
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.data import (
    ArrayDataType,
    EnumDataType,
    FunctionDefinitionDataType,
    PointerDataType,
    StructureDataType,
    TypedefDataType,
)
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import ConsoleTaskMonitor
from java.io import File

# Import shared utilities from ghidra_common
from ghidra_common import (
    GHIDRA_TYPE_MAP,
    UNKNOWN_TYPE_DEFS,
    demangle_cpp_name,
    enhance_decompiled_code,
    extract_class_from_method,
    extract_namespace,
    normalize_code_types,
    normalize_ghidra_type,
    sanitize_filename,
)

# ============================================================
# C++ Class and Virtual Function Analysis
# ============================================================


class CppClassInfo:
    """Information about a C++ class extracted from analysis"""

    def __init__(self, name):
        self.name = name
        self.methods = []  # [(func_name, display_name, is_virtual, vtable_index)]
        self.vtable_addr = None
        self.vtable_funcs = []  # [(index, func_addr, func_name)]
        self.struct_type = None  # Associated Ghidra struct type
        self.parent_class = None
        self.size = 0


def is_virtual_method(func, program):
    """
    Check if a function is likely a virtual method.

    Heuristics:
    1. Referenced in a vtable (data section with function pointers)
    2. Has __thiscall convention with 'this' as first param
    3. Name matches virtual method patterns
    """
    func_name = func.getName()

    # Check calling convention
    calling_conv = func.getCallingConventionName()
    if calling_conv and "thiscall" in calling_conv.lower():
        return True

    # Check if function is referenced from data section (potential vtable)
    refs = program.getReferenceManager().getReferencesTo(func.getEntryPoint())
    for ref in refs:
        if ref.getReferenceType().isData():
            from_addr = ref.getFromAddress()
            # Check if reference is from a potential vtable location
            mem = program.getMemory()
            block = mem.getBlock(from_addr)
            if block and (block.getName() in [".rodata", ".data", ".data.rel.ro"]):
                return True

    return False


def analyze_vtables(program, monitor):
    """
    Analyze virtual function tables in the program.

    Returns dict: vtable_addr -> [(index, func_addr, func_name)]
    """
    vtables = {}
    symbol_table = program.getSymbolTable()
    mem = program.getMemory()
    listing = program.getListing()

    # Look for symbols that match vtable patterns
    vtable_patterns = [
        r"^_ZTV",  # Itanium ABI: _ZTV<class>
        r"^vtable\s+for\s+",  # Demangled vtable
        r"^__vt_",  # Some compilers
        r"_vtbl$",  # ARM/RVCT pattern
    ]

    for symbol in symbol_table.getAllSymbols(True):
        if monitor.isCancelled():
            break

        sym_name = symbol.getName()
        sym_addr = symbol.getAddress()

        # Check if this looks like a vtable
        is_vtable = False
        class_name = None

        for pattern in vtable_patterns:
            if re.match(pattern, sym_name, re.IGNORECASE):
                is_vtable = True
                # Try to extract class name
                if sym_name.startswith("_ZTV"):
                    # Demangle
                    demangled = demangle_cpp_name(sym_name, program)
                    if "vtable for " in demangled:
                        class_name = demangled.replace("vtable for ", "").strip()
                    else:
                        class_name = sym_name[4:]  # Remove _ZTV prefix
                break

        if not is_vtable:
            continue

        # Parse vtable entries (array of function pointers)
        vtable_entries = []
        ptr_size = program.getDefaultPointerSize()
        current_addr = sym_addr
        index = 0

        # Skip RTTI pointer and offset-to-top (first 2 entries for Itanium ABI)
        # This is platform-specific, so we try to detect valid function pointers
        max_entries = 100  # Safety limit

        while index < max_entries:
            try:
                # Read pointer value
                if ptr_size == 4:
                    ptr_value = mem.getInt(current_addr)
                else:
                    ptr_value = mem.getLong(current_addr)

                # Check if this points to a function
                ptr_addr = (
                    program.getAddressFactory()
                    .getDefaultAddressSpace()
                    .getAddress(ptr_value)
                )
                func_at = listing.getFunctionAt(ptr_addr)

                if func_at:
                    vtable_entries.append((index, ptr_addr, func_at.getName()))
                    index += 1
                    current_addr = current_addr.add(ptr_size)
                elif index > 2:  # Allow first 2 entries to be non-functions (RTTI)
                    break
                else:
                    index += 1
                    current_addr = current_addr.add(ptr_size)

            except:
                break

        if vtable_entries:
            vtables[sym_addr] = {"class_name": class_name, "entries": vtable_entries}

    return vtables


def analyze_cpp_classes(program, module_functions, vtables, monitor):
    """
    Analyze C++ classes from function signatures and vtables.

    Returns dict: class_name -> CppClassInfo
    """
    classes = {}

    # Collect methods from function signatures
    for module_name, funcs in module_functions.items():
        for func, display_name, mangled_name in funcs:
            if monitor.isCancelled():
                break

            class_name = extract_class_from_method(display_name)
            if not class_name:
                continue

            if class_name not in classes:
                classes[class_name] = CppClassInfo(class_name)

            # Check if virtual
            is_virtual = is_virtual_method(func, program)
            vtable_index = -1

            # Find in vtables
            for vt_addr, vt_info in vtables.items():
                if vt_info["class_name"] == class_name:
                    for idx, func_addr, fname in vt_info["entries"]:
                        if func.getEntryPoint().equals(func_addr):
                            is_virtual = True
                            vtable_index = idx
                            break

            method_name = display_name.split("::")[-1].split("(")[0].strip()
            classes[class_name].methods.append(
                (func.getName(), method_name, is_virtual, vtable_index)
            )

    # Associate vtables with classes
    for vt_addr, vt_info in vtables.items():
        class_name = vt_info["class_name"]
        if class_name and class_name in classes:
            classes[class_name].vtable_addr = vt_addr
            classes[class_name].vtable_funcs = vt_info["entries"]

    return classes


def generate_class_header(output_dir, classes, program_name):
    """Generate a header file documenting discovered C++ classes"""
    if not classes:
        return None

    header_file = os.path.join(output_dir, "_classes.h")

    with open(header_file, "w") as f:
        f.write("/**\n")
        f.write(" * C++ Class Analysis\n")
        f.write(" * Source: {}\n".format(program_name))
        f.write(" * Classes found: {}\n".format(len(classes)))
        f.write(" *\n")
        f.write(" * Auto-generated by LibSurgeon\n")
        f.write(" * NOTE: This is analysis output, not compilable code\n")
        f.write(" */\n\n")

        f.write("#ifndef _CLASSES_H_\n")
        f.write("#define _CLASSES_H_\n\n")

        f.write('#include "_types.h"\n\n')

        # Write class declarations
        for class_name in sorted(classes.keys()):
            cls = classes[class_name]
            f.write("/* " + "=" * 56 + " */\n")
            f.write("/* Class: {} */\n".format(class_name))
            f.write("/* " + "=" * 56 + " */\n\n")

            # Virtual table info
            if cls.vtable_addr:
                f.write(
                    "/* VTable at: 0x{:08x} */\n".format(cls.vtable_addr.getOffset())
                )
                f.write("/* Virtual methods: {} */\n".format(len(cls.vtable_funcs)))

                if cls.vtable_funcs:
                    f.write("/*\n")
                    f.write(" * Virtual Function Table:\n")
                    for idx, func_addr, func_name in cls.vtable_funcs:
                        f.write(
                            " *   [{}] {} @ 0x{:08x}\n".format(
                                idx, func_name, func_addr.getOffset()
                            )
                        )
                    f.write(" */\n")
                f.write("\n")

            # Class declaration (forward)
            safe_name = class_name.replace("::", "_")
            f.write("typedef struct {} {};\n".format(safe_name, safe_name))
            f.write("struct {} {{\n".format(safe_name))

            # Add vtable pointer if class has virtual methods
            if cls.vtable_funcs:
                f.write("    void **_vptr;  /* Virtual function table pointer */\n")

            f.write("    /* TODO: Add member fields based on analysis */\n")
            f.write("}};\n\n")

            # Method declarations
            f.write("/* Methods ({}) */\n".format(len(cls.methods)))
            for mangled, method_name, is_virtual, vt_idx in sorted(
                cls.methods, key=lambda x: x[1]
            ):
                virtual_mark = (
                    "[virtual:{}] ".format(vt_idx) if is_virtual and vt_idx >= 0 else ""
                )
                virtual_kw = "virtual " if is_virtual else ""
                f.write("/* {}{}{} */\n".format(virtual_mark, virtual_kw, method_name))
            f.write("\n")

        f.write("#endif /* _CLASSES_H_ */\n")

    return header_file


def get_decompiled_function_elf(
    decomp_ifc, func, monitor, class_info=None, struct_info=None
):
    """
    Decompile a single function and return C code with normalized types.

    ELF-specific version with class/struct enhancement.
    """
    try:
        results = decomp_ifc.decompileFunction(func, 60, monitor)
        if results and results.decompileCompleted():
            code = results.getDecompiledFunction().getC()
            # Normalize Ghidra-specific types to standard C types
            code = normalize_code_types(code)
            # Enhance with class/struct analysis
            code = enhance_decompiled_code(code, class_info or {}, struct_info or {})
            return code
    except Exception as e:
        print("  [Error] Failed to decompile {}: {}".format(func.getName(), str(e)))
    return None


# ============================================================
# Module Grouping Strategies
# ============================================================


def extract_prefix(func_name, min_prefix_len=2, max_prefix_len=30):
    """
    Extract meaningful prefix from function name for grouping.

    Examples:
        xxBmpInit -> xxBmp
        xxFntGetMetrics -> xxFnt
        GfxCreateSurface -> Gfx
        vg_lite_init -> vg_lite
        ApplicationApplication_goHome -> ApplicationApplication
        CoreView__ReInit -> CoreView
    """
    # Skip auto-generated names
    if func_name.startswith("FUN_") or func_name.startswith("DAT_"):
        return "_generated"

    # Handle C-style underscore names with double underscore as separator
    # e.g., CoreView__ReInit -> CoreView
    if "__" in func_name:
        parts = func_name.split("__")
        if len(parts) >= 1 and len(parts[0]) >= min_prefix_len:
            return parts[0]

    # Handle single underscore as method separator
    # e.g., ApplicationApplication_goHome -> ApplicationApplication
    if "_" in func_name and not func_name.startswith("_"):
        parts = func_name.split("_")
        if len(parts) >= 2:
            # Check if first part looks like a class/module name (CamelCase or all caps)
            first_part = parts[0]
            if len(first_part) >= min_prefix_len:
                # If it's CamelCase or reasonable length, use it
                if re.match(r"^[A-Z][a-zA-Z0-9]+$", first_part) or len(first_part) >= 4:
                    return first_part
            # Try first two parts for compound names
            if len(parts) >= 2:
                compound = parts[0] + parts[1]
                if len(compound) <= max_prefix_len:
                    return compound

    # Handle pure CamelCase names
    # Find the first "word boundary" after initial capitals
    # xxBmpInit -> xxBmp, CoreView -> Core
    match = re.match(r"^([A-Z][a-z]+[A-Z][a-z]*)", func_name)
    if match:
        prefix = match.group(1)
        if min_prefix_len <= len(prefix) <= max_prefix_len:
            return prefix

    # Simpler pattern: First CamelCase word
    match = re.match(r"^([A-Z][a-z]+)", func_name)
    if match and len(match.group(1)) >= min_prefix_len:
        return match.group(1)

    # Lowercase prefix (c-style: vg_lite_init)
    match = re.match(r"^([a-z][a-z0-9]*_[a-z0-9]+)", func_name)
    if match:
        return match.group(1)

    # Just first lowercase word
    match = re.match(r"^([a-z]+)", func_name)
    if match and len(match.group(1)) >= min_prefix_len:
        return match.group(1)

    # All caps prefix (HAL_Init -> HAL)
    match = re.match(r"^([A-Z]+)_", func_name)
    if match and len(match.group(1)) >= min_prefix_len:
        return match.group(1)

    return "_misc"


def get_module_name_by_alpha(func_name, display_name):
    """Get module name using alphabetic strategy (A-Z)"""
    name_to_check = display_name if display_name else func_name

    # Skip auto-generated names
    if name_to_check.startswith("FUN_") or name_to_check.startswith("DAT_"):
        return "_generated"

    first_char = name_to_check[0].upper() if name_to_check else "_"
    if first_char.isalpha():
        return first_char
    return "_symbols"


def get_module_name_by_camelcase(func_name, display_name):
    """Get module name using CamelCase word extraction"""
    name_to_check = display_name if display_name else func_name

    # Skip auto-generated names
    if name_to_check.startswith("FUN_") or name_to_check.startswith("DAT_"):
        return "_generated"

    # Extract CamelCase words
    if "_" in name_to_check:
        words = name_to_check.split("_")
    else:
        words = re.findall(r"[A-Z][a-z]*|[a-z]+|[0-9]+", name_to_check)

    if len(words) >= 2:
        return words[0] + words[1]
    elif len(words) == 1:
        return words[0]
    return "_misc"


def get_module_name(func_name, display_name, strategy="prefix"):
    """Get module name based on specified strategy"""
    name_to_check = display_name if display_name else func_name

    if strategy == "prefix":
        return extract_prefix(name_to_check)
    elif strategy == "alpha":
        return get_module_name_by_alpha(func_name, display_name)
    elif strategy == "camelcase":
        return get_module_name_by_camelcase(func_name, display_name)
    elif strategy == "single":
        return "all_functions"
    else:
        return extract_prefix(name_to_check)


def write_file_header(f, module_name, func_count):
    """Write file header for a module"""
    f.write("/**\n")
    f.write(" * Module: {}\n".format(module_name))
    f.write(" * Functions: {}\n".format(func_count))
    f.write(" * \n")
    f.write(" * Generated by LibSurgeon (Ghidra-based decompiler)\n")
    f.write(" * \n")
    f.write(
        " * WARNING: This is automatically generated code from reverse engineering.\n"
    )
    f.write(
        " * It may not compile directly and is intended for educational purposes only.\n"
    )
    f.write(" */\n\n")

    f.write("#include <stdint.h>\n")
    f.write("#include <stdbool.h>\n")
    f.write("#include <stddef.h>\n")
    f.write('#include "../include/_types.h"\n\n')


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

    # Normalize types in the signature (already done in decompiled code, but just in case)
    signature = normalize_code_types(signature)

    return signature


def generate_header_file(output_dir, module_name, func_signatures):
    """Generate a header file for a module with function declarations."""
    safe_name = sanitize_filename(module_name)
    header_file = os.path.join(output_dir, "{}.h".format(safe_name))

    guard_name = "_{}_H_".format(safe_name.upper())

    with open(header_file, "w") as f:
        f.write("/**\n")
        f.write(" * Header: {}.h\n".format(safe_name))
        f.write(" * Module: {}\n".format(module_name))
        f.write(" * Functions: {}\n".format(len(func_signatures)))
        f.write(" * \n")
        f.write(" * Auto-generated by LibSurgeon from ELF decompilation\n")
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
    """Generate a master header file that includes all module headers."""
    header_file = os.path.join(output_dir, "_all_headers.h")

    with open(header_file, "w") as f:
        f.write("/**\n")
        f.write(" * Master Header File\n")
        f.write(" * Source: {}\n".format(program_name))
        f.write(" * Modules: {}\n".format(len(module_names)))
        f.write(" * \n")
        f.write(" * Auto-generated by LibSurgeon from ELF decompilation\n")
        f.write(" * Include this file to get all function declarations.\n")
        f.write(" */\n\n")

        f.write("#ifndef _ALL_HEADERS_H_\n")
        f.write("#define _ALL_HEADERS_H_\n\n")

        for module_name in sorted(module_names):
            safe_name = sanitize_filename(module_name)
            f.write('#include "{}.h"\n'.format(safe_name))

        f.write("\n#endif /* _ALL_HEADERS_H_ */\n")

    return header_file


def format_data_type(dt, indent=0):
    """Format a Ghidra DataType to C code string"""
    if dt is None:
        return None

    type_name = dt.getName()

    # Apply type normalization
    if type_name in GHIDRA_TYPE_MAP:
        return GHIDRA_TYPE_MAP[type_name]

    return type_name


def extract_struct_definition(dt, indent=0):
    """Extract C struct/enum definition from a Ghidra DataType"""
    indent_str = "    " * indent

    type_name = dt.getName()

    # Handle Structures
    if isinstance(dt, StructureDataType):
        lines = []
        lines.append("{}typedef struct {} {{".format(indent_str, type_name))

        for component in dt.getComponents():
            comp_name = component.getFieldName()
            comp_type = component.getDataType()
            comp_offset = component.getOffset()
            comp_size = component.getLength()

            if comp_name is None:
                comp_name = "field_0x{:x}".format(comp_offset)

            # Get type string with normalization
            type_str = format_data_type(comp_type)
            if type_str is None:
                type_str = comp_type.getDisplayName()

            # Normalize the type
            type_str = normalize_ghidra_type(type_str)

            # Handle arrays
            if isinstance(comp_type, ArrayDataType):
                elem_type = comp_type.getDataType()
                elem_type_str = format_data_type(elem_type)
                if elem_type_str is None:
                    elem_type_str = elem_type.getDisplayName()
                elem_type_str = normalize_ghidra_type(elem_type_str)
                array_len = comp_type.getNumElements()
                lines.append(
                    "{}    {} {}[{}];  /* offset: 0x{:x}, size: {} */".format(
                        indent_str,
                        elem_type_str,
                        comp_name,
                        array_len,
                        comp_offset,
                        comp_size,
                    )
                )
            else:
                lines.append(
                    "{}    {} {};  /* offset: 0x{:x}, size: {} */".format(
                        indent_str, type_str, comp_name, comp_offset, comp_size
                    )
                )

        lines.append(
            "{}}} {};  /* size: {} */".format(indent_str, type_name, dt.getLength())
        )
        return "\n".join(lines)

    # Handle Enums
    elif isinstance(dt, EnumDataType):
        lines = []
        lines.append("{}typedef enum {} {{".format(indent_str, type_name))

        values = list(dt.getValues())
        for i, value in enumerate(sorted(values)):
            name = dt.getName(value)
            suffix = "," if i < len(values) - 1 else ""
            lines.append("{}    {} = {}{}".format(indent_str, name, value, suffix))

        lines.append("{}}} {};".format(indent_str, type_name))
        return "\n".join(lines)

    # Handle Typedefs
    elif isinstance(dt, TypedefDataType):
        base_type = dt.getBaseDataType()
        base_name = format_data_type(base_type)
        if base_name is None:
            base_name = base_type.getDisplayName()
        base_name = normalize_ghidra_type(base_name)
        return "{}typedef {} {};".format(indent_str, base_name, type_name)

    return None


def collect_data_types(program):
    """Collect all user-defined data types from the program"""
    dtm = program.getDataTypeManager()

    structs = []
    enums = []
    typedefs = []

    # Iterate through all data types
    for dt in dtm.getAllDataTypes():
        category = dt.getCategoryPath().getPath()

        # Skip built-in types and library types
        if category.startswith("/"):
            cat_parts = category.split("/")
            if len(cat_parts) > 1 and cat_parts[1] in ["BuiltInTypes", "windows"]:
                continue

        name = dt.getName()

        # Skip anonymous types and Ghidra internal types
        if name.startswith("_") and name[1:].isdigit():
            continue
        if name.startswith("undefined"):
            continue

        if isinstance(dt, StructureDataType):
            structs.append(dt)
        elif isinstance(dt, EnumDataType):
            enums.append(dt)
        elif isinstance(dt, TypedefDataType):
            typedefs.append(dt)

    return structs, enums, typedefs


def generate_types_header(output_dir, program_name, structs, enums, typedefs):
    """Generate a header file containing all extracted types"""
    header_file = os.path.join(output_dir, "_types.h")

    with open(header_file, "w") as f:
        f.write("/**\n")
        f.write(" * Data Types Header\n")
        f.write(" * Source: {}\n".format(program_name))
        f.write(" * Structures: {}\n".format(len(structs)))
        f.write(" * Enums: {}\n".format(len(enums)))
        f.write(" * Typedefs: {}\n".format(len(typedefs)))
        f.write(" * \n")
        f.write(" * Auto-generated by LibSurgeon from ELF decompilation\n")
        f.write(" */\n\n")

        f.write("#ifndef _TYPES_H_\n")
        f.write("#define _TYPES_H_\n\n")

        f.write("#include <stdint.h>\n")
        f.write("#include <stdbool.h>\n")
        f.write("#include <stddef.h>\n\n")

        # Write unknown type definitions first
        f.write(UNKNOWN_TYPE_DEFS)
        f.write("\n")

        # Write forward declarations for structures
        if structs:
            f.write("/* Forward Declarations */\n")
            for dt in sorted(structs, key=lambda x: x.getName()):
                f.write("struct {};\n".format(dt.getName()))
            f.write("\n")

        # Write enums
        if enums:
            f.write("/* ============================================ */\n")
            f.write("/*                    ENUMS                     */\n")
            f.write("/* ============================================ */\n\n")
            for dt in sorted(enums, key=lambda x: x.getName()):
                definition = extract_struct_definition(dt)
                if definition:
                    f.write(definition)
                    f.write("\n\n")

        # Write typedefs
        if typedefs:
            f.write("/* ============================================ */\n")
            f.write("/*                   TYPEDEFS                   */\n")
            f.write("/* ============================================ */\n\n")
            for dt in sorted(typedefs, key=lambda x: x.getName()):
                definition = extract_struct_definition(dt)
                if definition:
                    f.write(definition)
                    f.write("\n")
            f.write("\n")

        # Write structures
        if structs:
            f.write("/* ============================================ */\n")
            f.write("/*                  STRUCTURES                  */\n")
            f.write("/* ============================================ */\n\n")
            for dt in sorted(structs, key=lambda x: x.getName()):
                definition = extract_struct_definition(dt)
                if definition:
                    f.write(definition)
                    f.write("\n\n")

        f.write("#endif /* _TYPES_H_ */\n")

    return header_file


def main():
    print("=" * 60)
    print("LibSurgeon - ELF Decompilation Script (Module Grouping)")
    print("=" * 60)

    # Get output directory and strategy from script arguments
    args = getScriptArgs()
    output_dir = "/tmp/libsurgeon_decompiled"
    strategy = "prefix"  # Default strategy

    if args:
        if len(args) > 0:
            output_dir = args[0]
        if len(args) > 1:
            strategy = args[1]

    # Get current program name
    program_name = currentProgram.getName()
    print("\n[Info] Processing: {}".format(program_name))
    print("[Info] Output directory: {}".format(output_dir))
    print("[Info] Grouping strategy: {}".format(strategy))

    # Create output directories (src for .cpp, include for .h)
    output_path = File(output_dir)
    if not output_path.exists():
        output_path.mkdirs()

    src_dir = os.path.join(output_dir, "src")
    include_dir = os.path.join(output_dir, "include")

    src_path = File(src_dir)
    if not src_path.exists():
        src_path.mkdirs()

    include_path = File(include_dir)
    if not include_path.exists():
        include_path.mkdirs()

    print("[Info] Source directory: {}".format(src_dir))
    print("[Info] Include directory: {}".format(include_dir))

    # Initialize decompiler
    monitor = ConsoleTaskMonitor()
    decomp_ifc = DecompInterface()

    if not decomp_ifc.openProgram(currentProgram):
        print("[Error] Failed to open program in decompiler")
        return

    # Configure decompiler options
    try:
        decomp_options = decomp_ifc.getOptions()
        if decomp_options is not None:
            decomp_options.setEliminateUnreachable(True)
    except:
        print("[Warn] Could not configure decompiler options")

    # Extract data types (structures, enums, typedefs)
    print("\n[Info] Extracting data types...")
    structs, enums, typedefs = collect_data_types(currentProgram)
    print(
        "[Info] Found {} structures, {} enums, {} typedefs".format(
            len(structs), len(enums), len(typedefs)
        )
    )

    if structs or enums or typedefs:
        types_header = generate_types_header(
            include_dir, program_name, structs, enums, typedefs
        )
        print("[Info] Generated types header: include/_types.h")

    # Get all functions
    func_manager = currentProgram.getFunctionManager()
    functions = func_manager.getFunctions(True)

    # Collect all functions and group by module
    print("\n[Info] Analyzing functions...")

    module_functions = defaultdict(
        list
    )  # module_name -> [(func, display_name, mangled_name)]
    namespaces_found = set()
    func_count = 0
    thunk_count = 0
    external_count = 0

    for func in functions:
        if monitor.isCancelled():
            break

        func_name = func.getName()

        # Skip thunks and external functions
        if func.isThunk():
            thunk_count += 1
            continue
        if func.isExternal():
            external_count += 1
            continue

        # Try to demangle C++ names
        display_name = func_name
        if func_name.startswith("_Z"):
            demangled = demangle_cpp_name(func_name, currentProgram)
            if demangled and demangled != func_name:
                display_name = demangled
                # Track namespace
                ns = extract_namespace(demangled)
                if ns:
                    namespaces_found.add(ns)

        # Determine module
        module_name = get_module_name(func_name, display_name, strategy)
        module_functions[module_name].append((func, display_name, func_name))
        func_count += 1

    print("[Info] Found {} functions to decompile".format(func_count))
    print("[Info] Skipped {} thunks, {} externals".format(thunk_count, external_count))
    print("[Info] Grouped into {} modules".format(len(module_functions)))

    if namespaces_found:
        print("[Info] C++ Namespaces: {}".format(", ".join(sorted(namespaces_found))))

    # Analyze C++ virtual tables
    print("\n[Info] Analyzing virtual function tables...")
    vtables = analyze_vtables(currentProgram, monitor)
    print("[Info] Found {} vtables".format(len(vtables)))

    # Analyze C++ classes
    print("[Info] Analyzing C++ classes...")
    cpp_classes = analyze_cpp_classes(
        currentProgram, module_functions, vtables, monitor
    )
    print("[Info] Found {} C++ classes".format(len(cpp_classes)))

    # Count virtual methods
    virtual_method_count = sum(
        1
        for cls in cpp_classes.values()
        for _, _, is_virtual, _ in cls.methods
        if is_virtual
    )
    if virtual_method_count > 0:
        print("[Info] Identified {} virtual methods".format(virtual_method_count))

    # Generate class header
    if cpp_classes:
        class_header = generate_class_header(include_dir, cpp_classes, program_name)
        if class_header:
            print("[Info] Generated class header: include/_classes.h")

    # Build struct info map for code enhancement
    struct_info = {}
    for s in structs:
        struct_info[s.getName()] = s

    # Print module summary (top 20)
    print("\n[Info] Module breakdown (top 20):")
    sorted_modules = sorted(module_functions.items(), key=lambda x: -len(x[1]))
    for module_name, funcs in sorted_modules[:20]:
        print("  - {}: {} functions".format(module_name, len(funcs)))
    if len(sorted_modules) > 20:
        print("  ... and {} more modules".format(len(sorted_modules) - 20))

    # Decompile and write each module
    print("\n[Info] Decompiling modules...")

    # Output progress header for shell script to parse
    print("[PROGRESS_TOTAL] {}".format(func_count))

    total_decompiled = 0
    total_failed = 0
    current_func = 0
    module_index = 0
    total_modules = len(module_functions)

    # Store function signatures for header file generation
    module_signatures = defaultdict(list)  # module_name -> [(func_name, signature)]

    for module_name in sorted(module_functions.keys()):
        funcs = module_functions[module_name]
        module_index += 1

        # Create output filename in src directory
        safe_module_name = sanitize_filename(module_name)
        output_file = os.path.join(src_dir, "{}.cpp".format(safe_module_name))

        # Only print module info for first 5 and last one, or if total <= 10
        if total_modules <= 10 or module_index <= 5 or module_index == total_modules:
            print(
                "\n  [{}/{}] Processing module: {} ({} functions)".format(
                    module_index, total_modules, module_name, len(funcs)
                )
            )
        elif module_index == 6:
            print("\n  ... processing {} more modules ...".format(total_modules - 6))

        module_decompiled = 0
        module_failed = 0

        with open(output_file, "w") as f:
            write_file_header(f, module_name, len(funcs))

            # Add include for the module's own header (in ../include/)
            f.write('#include "../include/{}.h"\n\n'.format(safe_module_name))

            # Sort functions by display name
            sorted_funcs = sorted(funcs, key=lambda x: x[1])

            for func, display_name, mangled_name in sorted_funcs:
                if monitor.isCancelled():
                    break

                current_func += 1
                # Output progress for shell script to parse
                print(
                    "[PROGRESS] {}/{} {}".format(
                        current_func, func_count, display_name[:50]
                    )
                )

                # Decompile with class/struct enhancement
                decompiled = get_decompiled_function_elf(
                    decomp_ifc, func, monitor, cpp_classes, struct_info
                )

                if decompiled:
                    # Extract signature for header file
                    signature = extract_function_signature(decompiled)
                    if signature:
                        module_signatures[module_name].append((display_name, signature))

                    # Check if this is a virtual method
                    class_name = extract_class_from_method(display_name)
                    is_virtual = False
                    vtable_idx = -1
                    if class_name and class_name in cpp_classes:
                        for m_mangled, m_name, m_virtual, m_idx in cpp_classes[
                            class_name
                        ].methods:
                            if m_mangled == mangled_name:
                                is_virtual = m_virtual
                                vtable_idx = m_idx
                                break

                    f.write("// " + "=" * 60 + "\n")
                    f.write("// Function: {}\n".format(display_name))
                    if mangled_name != display_name:
                        f.write("// Mangled: {}\n".format(mangled_name))
                    if class_name:
                        f.write("// Class: {}\n".format(class_name))
                    if is_virtual:
                        if vtable_idx >= 0:
                            f.write(
                                "// Virtual: Yes (vtable index {})\n".format(vtable_idx)
                            )
                        else:
                            f.write("// Virtual: Yes\n")
                    f.write(
                        "// Address: 0x{:08x}\n".format(
                            func.getEntryPoint().getOffset()
                        )
                    )
                    f.write("// " + "=" * 60 + "\n\n")
                    f.write(decompiled)
                    f.write("\n")
                    module_decompiled += 1
                else:
                    f.write(
                        "// [FAILED] Could not decompile: {}\n".format(display_name)
                    )
                    f.write(
                        "// Address: 0x{:08x}\n\n".format(
                            func.getEntryPoint().getOffset()
                        )
                    )
                    module_failed += 1

        # Only print result for first 5 and last one, or if total <= 10
        if total_modules <= 10 or module_index <= 5 or module_index == total_modules:
            print(
                "    -> {}.cpp: {} OK, {} failed".format(
                    safe_module_name, module_decompiled, module_failed
                )
            )

        total_decompiled += module_decompiled

        total_failed += module_failed

    # Close decompiler
    decomp_ifc.dispose()

    # Generate header files
    print("\n[Info] Generating header files...")
    header_count = 0
    total_signatures = 0

    for module_name in sorted(module_signatures.keys()):
        signatures = module_signatures[module_name]
        if signatures:
            generate_header_file(include_dir, module_name, signatures)
            header_count += 1
            total_signatures += len(signatures)

    # Generate master header
    if header_count > 0:
        generate_master_header(include_dir, module_signatures.keys(), program_name)
        print(
            "[Info] Generated {} header files with {} function declarations".format(
                header_count, total_signatures
            )
        )
        print("[Info] Master header: include/_all_headers.h")

    # Generate index file
    index_file = os.path.join(output_dir, "_INDEX.md")
    with open(index_file, "w") as f:
        f.write("# Decompilation Index\n\n")
        f.write("Source: {}\n\n".format(program_name))
        f.write("## Summary\n")
        f.write("- Total functions: {}\n".format(func_count))
        f.write("- Successfully decompiled: {}\n".format(total_decompiled))
        f.write("- Failed: {}\n".format(total_failed))
        f.write("- Grouping strategy: {}\n".format(strategy))
        f.write("- Output modules: {}\n".format(len(module_functions)))
        f.write("- Header files: {}\n".format(header_count))
        f.write("- Function declarations: {}\n".format(total_signatures))
        f.write("- C++ Classes: {}\n".format(len(cpp_classes)))
        f.write("- Virtual Tables: {}\n".format(len(vtables)))
        f.write("- Virtual Methods: {}\n\n".format(virtual_method_count))

        # C++ Class summary
        if cpp_classes:
            f.write("## C++ Classes\n\n")
            f.write("| Class | Methods | Virtual | VTable |\n")
            f.write("|-------|---------|---------|--------|\n")
            for class_name in sorted(cpp_classes.keys()):
                cls = cpp_classes[class_name]
                virt_count = sum(1 for _, _, is_v, _ in cls.methods if is_v)
                has_vtable = "Yes" if cls.vtable_addr else "No"
                f.write(
                    "| {} | {} | {} | {} |\n".format(
                        class_name, len(cls.methods), virt_count, has_vtable
                    )
                )
            f.write("\n")

        f.write("## Modules\n\n")
        f.write("| Module | Functions | Source | Header |\n")
        f.write("|--------|-----------|--------|--------|\n")
        for module_name in sorted(module_functions.keys()):
            count = len(module_functions[module_name])
            safe_name = sanitize_filename(module_name)
            sig_count = len(module_signatures.get(module_name, []))
            f.write(
                "| {} | {} | `src/{}.cpp` | `include/{}.h` ({}) |\n".format(
                    module_name, count, safe_name, safe_name, sig_count
                )
            )

        f.write("\n## Function List by Module\n\n")
        for module_name in sorted(module_functions.keys()):
            f.write("### {}\n\n".format(module_name))
            for func, display_name, mangled_name in sorted(
                module_functions[module_name], key=lambda x: x[1]
            ):
                addr = "0x{:08x}".format(func.getEntryPoint().getOffset())
                f.write("- `{}` @ {}\n".format(display_name, addr))
            f.write("\n")

    print("\n" + "=" * 60)
    print("[Result] Decompilation complete!")
    print("  - Total functions: {}".format(func_count))
    print("  - Successfully decompiled: {}".format(total_decompiled))
    print("  - Failed: {}".format(total_failed))
    print("  - Output modules: {}".format(len(module_functions)))
    print("  - Header files: {}".format(header_count))
    print("  - Index file: {}".format(index_file))
    print("=" * 60)


# Run main function
if __name__ == "__main__":
    main()
else:
    # Running as script in Ghidra
    main()
