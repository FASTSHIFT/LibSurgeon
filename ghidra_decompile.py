#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LibSurgeon - Ghidra Headless Decompilation Script

This script runs in Ghidra's Headless mode to automatically analyze
and decompile object files (.o) from static libraries (.a).
"""

# Ghidra Python scripts use Jython with Ghidra's API
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SourceType
from java.io import File
import os
import re


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
    # Remove or replace illegal characters
    name = re.sub(r'[<>:"/\\|?*]', "_", name)
    name = re.sub(r"\s+", "_", name)
    # Limit length
    if len(name) > 200:
        name = name[:200]
    return name


def extract_class_name(func_name):
    """Extract class name from function name"""
    # Try to extract class name from namespace::class::method format
    if "::" in func_name:
        parts = func_name.split("::")
        if len(parts) >= 2:
            # Usually namespace::class::method
            return parts[-2] if len(parts) > 2 else parts[0]
    return None


def extract_namespace(func_name):
    """Extract top-level namespace from function name"""
    if "::" in func_name:
        parts = func_name.split("::")
        if len(parts) >= 1:
            return parts[0]
    return None


def main():
    print("=" * 60)
    print("LibSurgeon - Ghidra Decompilation Script")
    print("=" * 60)

    # Get output directory from script arguments
    args = getScriptArgs()
    if args and len(args) > 0:
        output_dir = args[0]
    else:
        output_dir = "/tmp/libsurgeon_decompiled"

    # Get current program name
    program_name = currentProgram.getName()
    print("\n[Info] Processing: {}".format(program_name))
    print("[Info] Output directory: {}".format(output_dir))

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
    for func in functions:
        if monitor.isCancelled():
            break

        func_name = func.getName()

        # Try to demangle
        if func_name.startswith("_Z"):
            demangled = demangle_cpp_name(func_name)
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

    print("[Info] Found {} functions".format(func_count))
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
        f.write("/**\n")
        f.write(" * Auto-generated decompiled code from: {}\n".format(program_name))
        f.write(" * Generated by LibSurgeon (Ghidra-based decompiler)\n")
        f.write(" * \n")
        f.write(
            " * WARNING: This is automatically generated code from reverse engineering.\n"
        )
        f.write(
            " * It may not compile directly and is intended for educational purposes only.\n"
        )
        f.write(" */\n\n")

        # Write common includes
        f.write("// Common includes (may need adjustment)\n")
        f.write("#include <stdint.h>\n")
        f.write("#include <stdbool.h>\n")
        f.write("#include <stddef.h>\n\n")

        # Detect and write namespace
        primary_namespace = None
        if namespaces_found:
            # Use the most common namespace
            primary_namespace = sorted(namespaces_found)[0]
            f.write("namespace {} {{\n\n".format(primary_namespace))

        # Write decompiled code organized by class
        for class_name, funcs in sorted(class_functions.items()):
            f.write("// ============================================================\n")
            f.write("// Class: {}\n".format(class_name))
            f.write(
                "// ============================================================\n\n"
            )

            for func, demangled_name in funcs:
                decompiled = get_decompiled_function(decomp_ifc, func, monitor)
                if decompiled:
                    f.write("// Original: {}\n".format(func.getName()))
                    f.write("// Demangled: {}\n".format(demangled_name))
                    f.write(decompiled)
                    f.write("\n")
                    decompiled_count += 1
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
                decompiled = get_decompiled_function(decomp_ifc, func, monitor)
                if decompiled:
                    f.write("// Function: {}\n".format(display_name))
                    f.write(decompiled)
                    f.write("\n")
                    decompiled_count += 1
                else:
                    f.write(
                        "// [FAILED] Could not decompile: {}\n\n".format(display_name)
                    )
                    failed_count += 1

        # Close namespace if used
        if primary_namespace:
            f.write("}} // namespace {}\n".format(primary_namespace))

    # Close decompiler
    decomp_ifc.dispose()

    print("\n[Result] Decompilation complete!")
    print("  - Successfully decompiled: {} functions".format(decompiled_count))
    print("  - Failed: {} functions".format(failed_count))
    print("  - Output file: {}".format(output_file))


# Run main function
if __name__ == "__main__":
    main()
else:
    # Running as script in Ghidra
    main()
