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
from java.io import File
import os
import re
from collections import defaultdict


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
    """Decompile a single function and return C code"""
    try:
        results = decomp_ifc.decompileFunction(func, 60, monitor)
        if results and results.decompileCompleted():
            return results.getDecompiledFunction().getC()
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
    f.write("#include <stddef.h>\n\n")


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

    # Create output directory
    output_path = File(output_dir)
    if not output_path.exists():
        output_path.mkdirs()

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

    for module_name in sorted(module_functions.keys()):
        funcs = module_functions[module_name]
        module_index += 1

        # Create output filename - just use module name, no ELF prefix!
        safe_module_name = sanitize_filename(module_name)
        output_file = os.path.join(output_dir, "{}.cpp".format(safe_module_name))

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
        f.write("- Output modules: {}\n\n".format(len(module_functions)))

        f.write("## Modules\n\n")
        f.write("| Module | Functions | File |\n")
        f.write("|--------|-----------|------|\n")
        for module_name in sorted(module_functions.keys()):
            count = len(module_functions[module_name])
            safe_name = sanitize_filename(module_name)
            f.write("| {} | {} | `{}.cpp` |\n".format(module_name, count, safe_name))

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
    print("  - Index file: {}".format(index_file))
    print("=" * 60)


# Run main function
if __name__ == "__main__":
    main()
else:
    # Running as script in Ghidra
    main()
