#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LibSurgeon - Ghidra Headless Decompilation Script for ELF Files

This script runs in Ghidra's Headless mode to automatically analyze
and decompile ELF files with intelligent module grouping.

Functions with the same prefix are grouped into the same output file.

Module Grouping Strategies:
  - prefix: Group by function name prefix (e.g., EwBmp*, EwFnt*)
  - alpha: Group by first letter (A-Z)
  - camelcase: Extract CamelCase words as module names
  - single: All functions in one file
"""

# Ghidra Python scripts use Jython with Ghidra's API
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import StructureDataType, EnumDataType, TypedefDataType
from ghidra.program.model.data import (
    ArrayDataType,
    PointerDataType,
    FunctionDefinitionDataType,
)
from java.io import File
import os
import re
from collections import defaultdict


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


def normalize_ghidra_type(type_str):
    """Convert Ghidra-specific types to standard C types"""
    if not type_str:
        return type_str

    original = type_str

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


def demangle_cpp_name(mangled_name):
    """Attempt to demangle C++ mangled names"""
    try:
        from ghidra.app.util.demangler import DemanglerUtil

        demangled = DemanglerUtil.demangle(currentProgram, mangled_name)
        if demangled:
            return demangled.getSignature(False)
    except:
        pass
    return mangled_name


def get_decompiled_function(decomp_ifc, func, monitor):
    """Decompile a single function and return C code with normalized types"""
    try:
        results = decomp_ifc.decompileFunction(func, 60, monitor)
        if results and results.decompileCompleted():
            code = results.getDecompiledFunction().getC()
            # Normalize Ghidra-specific types to standard C types
            return normalize_code_types(code)
    except Exception as e:
        print("  [Error] Failed to decompile {}: {}".format(func.getName(), str(e)))
    return None


def sanitize_filename(name):
    """Sanitize filename by removing illegal characters"""
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
    """Extract class name from function name"""
    if "::" in func_name:
        parts = func_name.split("::")
        if len(parts) >= 2:
            return parts[-2] if len(parts) > 2 else parts[0]
    return None


def extract_namespace(func_name):
    """Extract top-level namespace from function name"""
    if "::" in func_name:
        parts = func_name.split("::")
        if len(parts) >= 1:
            return parts[0]
    return None


# ============================================================
# Module Grouping Strategies
# ============================================================


def extract_prefix(func_name, min_prefix_len=2, max_prefix_len=30):
    """
    Extract meaningful prefix from function name for grouping.

    Examples:
        EwBmpInit -> EwBmp
        EwFntGetMetrics -> EwFnt
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
    # EwBmpInit -> EwBmp, CoreView -> Core
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
            demangled = demangle_cpp_name(func_name)
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

                decompiled = get_decompiled_function(decomp_ifc, func, monitor)

                if decompiled:
                    # Extract signature for header file
                    signature = extract_function_signature(decompiled)
                    if signature:
                        module_signatures[module_name].append((display_name, signature))

                    f.write("// " + "=" * 60 + "\n")
                    f.write("// Function: {}\n".format(display_name))
                    if mangled_name != display_name:
                        f.write("// Mangled: {}\n".format(mangled_name))
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
        f.write("- Function declarations: {}\n\n".format(total_signatures))

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
