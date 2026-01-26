#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LibSurgeon - Ghidra Headless Decompilation Script for Library Files

This script runs in Ghidra's Headless mode to automatically analyze
and decompile object files (.o) from static libraries (.a).

For ELF file processing, use ghidra_decompile_elf.py instead.
"""

import os
import sys

# Add the script's directory to Python path for importing ghidra_common
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

# Ghidra Python scripts use Jython with Ghidra's API
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from java.io import File

# Import shared utilities
from ghidra_common import (
    demangle_cpp_name,
    extract_class_name,
    extract_function_signature,
    extract_namespace,
    generate_header_file,
    generate_types_header,
    get_decompiled_function_basic,
    sanitize_filename,
    should_skip_function,
    write_file_header,
)


def main():
    print("=" * 60)
    print("LibSurgeon - Ghidra Decompilation Script (Library Mode)")
    print("=" * 60)

    # Get output directory from script arguments
    args = getScriptArgs()
    if args and len(args) > 0:
        output_dir = args[0]
    else:
        output_dir = "/tmp/libsurgeon_decompiled"

    # Get include directory from second argument (optional)
    if args and len(args) > 1:
        include_dir = args[1]
    else:
        # Default: create include dir alongside output_dir
        include_dir = os.path.join(os.path.dirname(output_dir), "include")

    # Get current program name
    program_name = currentProgram.getName()
    print("\n[Info] Processing: {}".format(program_name))
    print("[Info] Output directory: {}".format(output_dir))
    print("[Info] Include directory: {}".format(include_dir))

    # Create output directories
    output_path = File(output_dir)
    if not output_path.exists():
        output_path.mkdirs()
    include_path = File(include_dir)
    if not include_path.exists():
        include_path.mkdirs()

    # Initialize decompiler
    monitor = ConsoleTaskMonitor()
    decomp_ifc = DecompInterface()

    if not decomp_ifc.openProgram(currentProgram):
        print("[Error] Failed to open program in decompiler")
        return

    # Configure decompiler options (safe method)
    try:
        decomp_options = decomp_ifc.getOptions()
        if decomp_options is not None:
            decomp_options.setEliminateUnreachable(True)
    except:
        print("[Warn] Could not configure decompiler options")

    # Get all functions
    func_manager = currentProgram.getFunctionManager()
    functions = func_manager.getFunctions(True)

    # Organize functions by class/namespace
    class_functions = {}
    standalone_functions = []
    namespaces_found = set()

    func_count = 0
    skipped_count = 0
    for func in functions:
        if monitor.isCancelled():
            break

        # Skip external symbols and special sections
        if should_skip_function(func, currentProgram):
            skipped_count += 1
            continue

        func_name = func.getName()

        # Try to demangle
        if func_name.startswith("_Z"):
            demangled = demangle_cpp_name(func_name, currentProgram)
            if demangled and demangled != func_name:
                # Track namespace
                ns = extract_namespace(demangled)
                if ns:
                    namespaces_found.add(ns)

                class_name = extract_class_name(demangled)
                if class_name:
                    if class_name not in class_functions:
                        class_functions[class_name] = []
                    class_functions[class_name].append((func, demangled))
                else:
                    standalone_functions.append((func, demangled))
            else:
                standalone_functions.append((func, func_name))
        else:
            standalone_functions.append((func, func_name))

        func_count += 1

    print("[Info] Found {} functions to decompile".format(func_count))
    print("[Info] Skipped {} external/special functions".format(skipped_count))
    print("[Info] Found {} classes".format(len(class_functions)))
    if namespaces_found:
        print("[Info] Namespaces: {}".format(", ".join(sorted(namespaces_found))))

    # Generate output file
    # Use .o filename as base name
    base_name = program_name.replace(".o", "")
    output_file = os.path.join(
        output_dir, sanitize_filename(base_name) + "_decompiled.cpp"
    )

    decompiled_count = 0
    failed_count = 0

    with open(output_file, "w") as f:
        # Write file header
        write_file_header(f, base_name, func_count, program_name)

        # Detect and write namespace
        primary_namespace = None
        if namespaces_found:
            # Use the most common namespace
            primary_namespace = sorted(namespaces_found)[0]
            f.write("namespace {} {{\n\n".format(primary_namespace))

        # Collect function signatures for header generation
        func_signatures = []

        # Write decompiled code organized by class
        for class_name, funcs in sorted(class_functions.items()):
            f.write("// ============================================================\n")
            f.write("// Class: {}\n".format(class_name))
            f.write(
                "// ============================================================\n\n"
            )

            for func, demangled_name in funcs:
                decompiled = get_decompiled_function_basic(decomp_ifc, func, monitor)
                if decompiled:
                    f.write("// Original: {}\n".format(func.getName()))
                    f.write("// Demangled: {}\n".format(demangled_name))
                    f.write(decompiled)
                    f.write("\n")
                    decompiled_count += 1

                    # Extract function signature for header
                    signature = extract_function_signature(decompiled)
                    if signature:
                        func_signatures.append((demangled_name, signature))
                else:
                    f.write(
                        "// [FAILED] Could not decompile: {}\n\n".format(demangled_name)
                    )
                    failed_count += 1

        # Standalone functions
        if standalone_functions:
            f.write("// ============================================================\n")
            f.write("// Standalone Functions\n")
            f.write(
                "// ============================================================\n\n"
            )

            for func, display_name in standalone_functions:
                decompiled = get_decompiled_function_basic(decomp_ifc, func, monitor)
                if decompiled:
                    f.write("// Function: {}\n".format(display_name))
                    f.write(decompiled)
                    f.write("\n")
                    decompiled_count += 1

                    # Extract function signature for header
                    signature = extract_function_signature(decompiled)
                    if signature:
                        func_signatures.append((display_name, signature))
                else:
                    f.write(
                        "// [FAILED] Could not decompile: {}\n\n".format(display_name)
                    )
                    failed_count += 1

        # Close namespace if used
        if primary_namespace:
            f.write("}} // namespace {}\n".format(primary_namespace))

    # Generate header file to include directory
    header_file = None
    if func_signatures:
        header_file = generate_header_file(
            include_dir, base_name, func_signatures, "library decompilation"
        )
        # Also generate types header
        generate_types_header(include_dir)
        print("[Info] Generated header file: {}".format(header_file))

    # Close decompiler
    decomp_ifc.dispose()

    print("\n[Result] Decompilation complete!")
    print("  - Successfully decompiled: {} functions".format(decompiled_count))
    print("  - Failed: {} functions".format(failed_count))
    print("  - Output file: {}".format(output_file))
    if header_file:
        print("  - Header file: {}".format(header_file))


# Run main function
if __name__ == "__main__":
    main()
else:
    # Running as script in Ghidra
    main()
