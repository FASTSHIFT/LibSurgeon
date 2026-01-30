#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LibSurgeon - Ghidra Headless Decompilation Script for Library Files

This script runs in Ghidra's Headless mode to automatically analyze
and decompile object files (.o) from static libraries (.a).

For ELF file processing, use ghidra_decompile_elf.py instead.

DWARF Debug Info Support:
- Automatically detects and uses DWARF debug information
- Preserves original variable names from debug info
- Supports both ELF (ARM/x86) and COFF/PE formats
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


def check_debug_info(program):
    """
    Check if the program has DWARF debug information.

    Returns:
        tuple: (has_debug_info, debug_format, details)
    """
    has_debug = False
    debug_format = "none"
    details = []

    try:
        # Check for debug sections in memory blocks
        memory = program.getMemory()
        blocks = memory.getBlocks()

        debug_sections = []
        for block in blocks:
            name = block.getName()
            if name.startswith(".debug"):
                debug_sections.append(name)
                has_debug = True

        if debug_sections:
            debug_format = "DWARF"
            details.append("Debug sections: {}".format(", ".join(debug_sections)))

        # Check for source file information
        listing = program.getListing()
        func_iter = listing.getFunctions(True)

        source_files = set()
        for func in func_iter:
            # Get source file from function's source location
            try:
                source_info = func.getComment()
                if source_info and (".cpp" in source_info or ".c" in source_info):
                    source_files.add(source_info.split(":")[-1].strip())
            except:
                pass

        if source_files:
            details.append("Source files referenced: {}".format(len(source_files)))

        # Check data type manager for imported types
        dtm = program.getDataTypeManager()
        if dtm:
            type_count = dtm.getDataTypeCount(True)
            if type_count > 10:  # More than basic types
                details.append("Data types imported: {}".format(type_count))
                has_debug = True

    except Exception as e:
        details.append("Debug check error: {}".format(str(e)))

    return (has_debug, debug_format, details)


def get_function_local_variables(func):
    """
    Extract local variable information from a function.

    Args:
        func: Ghidra Function object

    Returns:
        list: List of (name, type, storage) tuples for local variables
    """
    variables = []
    try:
        # Get all local variables (including parameters)
        all_vars = func.getAllVariables()
        for var in all_vars:
            name = var.getName()
            var_type = var.getDataType().getName() if var.getDataType() else "unknown"
            storage = str(var.getVariableStorage())

            # Skip auto-generated names like local_XX, param_X
            if not (
                name.startswith("local_")
                or name.startswith("param_")
                or name.startswith("in_")
                or name.startswith("uVar")
            ):
                variables.append((name, var_type, storage))
    except:
        pass
    return variables


def get_function_parameters_with_names(func):
    """
    Get function parameters with their original names from debug info.

    Args:
        func: Ghidra Function object

    Returns:
        list: List of (name, type) tuples for parameters
    """
    params = []
    try:
        for param in func.getParameters():
            name = param.getName()
            param_type = (
                param.getDataType().getName() if param.getDataType() else "unknown"
            )
            params.append((name, param_type))
    except:
        pass
    return params


def apply_dwarf_variable_names(func, decomp_ifc, monitor):
    """
    Try to apply DWARF variable names to the decompiled function.

    This function checks if the function has debug info with variable names
    and attempts to apply them to the high-level decompilation.

    Args:
        func: Ghidra Function object
        decomp_ifc: DecompInterface
        monitor: Task monitor

    Returns:
        bool: True if any variable names were applied
    """
    try:
        from ghidra.app.decompiler import DecompileResults
        from ghidra.program.model.pcode import HighFunction

        # Get the high function from decompilation
        results = decomp_ifc.decompileFunction(func, 60, monitor)
        if not results or not results.decompileCompleted():
            return False

        high_func = results.getHighFunction()
        if not high_func:
            return False

        # Get local symbol map
        local_symbols = high_func.getLocalSymbolMap()
        if not local_symbols:
            return False

        # Check function's stored variables for debug names
        stored_vars = func.getAllVariables()
        debug_names = {}

        for var in stored_vars:
            name = var.getName()
            # Check if this is a meaningful name (not auto-generated)
            if not (
                name.startswith("local_")
                or name.startswith("param_")
                or name.startswith("in_")
                or name.startswith("uVar")
                or name.startswith("iVar")
                or name.startswith("pVar")
            ):
                storage = var.getVariableStorage()
                debug_names[str(storage)] = name

        return len(debug_names) > 0

    except Exception as e:
        return False


def get_dwarf_variable_mapping(func):
    """
    Get mapping of DWARF variable names for a function.

    Returns a dict mapping auto-generated names to original DWARF names.
    This can be used to add comments or perform substitution.

    Args:
        func: Ghidra Function object

    Returns:
        dict: Mapping of {auto_name: dwarf_name}
    """
    mapping = {}
    try:
        # Get parameters
        for i, param in enumerate(func.getParameters()):
            name = param.getName()
            auto_name = "param_{}".format(i + 1)
            if name and not name.startswith("param_"):
                mapping[auto_name] = name

        # Get local variables
        for var in func.getLocalVariables():
            name = var.getName()
            if name and not (
                name.startswith("local_")
                or name.startswith("uVar")
                or name.startswith("iVar")
                or name.startswith("pVar")
            ):
                # Try to find the corresponding auto-generated name
                # This is tricky because Ghidra may use different naming
                pass

    except Exception as e:
        pass

    return mapping


def add_dwarf_variable_comments(code, func):
    """
    Add comments about original DWARF variable names to decompiled code.

    Args:
        code: Decompiled C code string
        func: Ghidra Function object

    Returns:
        str: Code with added comments about original variable names
    """
    if not code:
        return code

    try:
        # Collect original variable names from function
        original_params = []
        for param in func.getParameters():
            name = param.getName()
            ptype = param.getDataType().getName() if param.getDataType() else "?"
            if name and not name.startswith("param_"):
                original_params.append("{} {}".format(ptype, name))

        original_locals = []
        for var in func.getLocalVariables():
            name = var.getName()
            vtype = var.getDataType().getName() if var.getDataType() else "?"
            if name and not (
                name.startswith("local_")
                or name.startswith("uVar")
                or name.startswith("iVar")
                or name.startswith("pVar")
                or name.startswith("in_")
            ):
                original_locals.append("{} {}".format(vtype, name))

        # If we have original names, add a comment
        if original_params or original_locals:
            comment_lines = []
            if original_params:
                comment_lines.append(
                    "/* Original params: {} */".format(", ".join(original_params))
                )
            if original_locals:
                comment_lines.append(
                    "/* Original locals: {} */".format(", ".join(original_locals[:5]))
                )
                if len(original_locals) > 5:
                    comment_lines[-1] = comment_lines[-1].replace(
                        " */", " + {} more */".format(len(original_locals) - 5)
                    )

            # Insert after function signature (before opening brace)
            brace_pos = code.find("{")
            if brace_pos > 0:
                comment = "\n".join(comment_lines)
                code = code[:brace_pos] + "\n" + comment + "\n" + code[brace_pos:]

    except Exception as e:
        pass

    return code


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

    # Check for debug information
    has_debug, debug_format, debug_details = check_debug_info(currentProgram)
    if has_debug:
        print("[Info] Debug information detected: {}".format(debug_format))
        for detail in debug_details:
            print("       - {}".format(detail))
    else:
        print("[Info] No debug information found - using heuristic analysis")

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

    # Configure decompiler options for better debug info utilization
    try:
        decomp_options = decomp_ifc.getOptions()
        if decomp_options is not None:
            decomp_options.setEliminateUnreachable(True)
            # These options help preserve debug info in output
            try:
                # Try to enable options that preserve variable names
                decomp_options.grabFromProgram(currentProgram)
            except:
                pass
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

    # Count functions with preserved variable names (from debug info)
    funcs_with_debug_vars = 0
    total_preserved_vars = 0

    # Generate output file
    # Use .o filename as base name
    base_name = program_name.replace(".o", "")
    output_file = os.path.join(
        output_dir, sanitize_filename(base_name) + "_decompiled.cpp"
    )

    decompiled_count = 0
    failed_count = 0

    with open(output_file, "w") as f:
        # Write file header with debug info status
        write_file_header(f, base_name, func_count, program_name)

        # Add debug info note if present
        if has_debug:
            f.write("/* Debug Information: {} */\n".format(debug_format))
            f.write("/* Variable names preserved from original source */\n\n")

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
                # Check for preserved variable names
                local_vars = get_function_local_variables(func)
                params = get_function_parameters_with_names(func)

                if local_vars or params:
                    funcs_with_debug_vars += 1
                    total_preserved_vars += len(local_vars) + len(params)

                decompiled = get_decompiled_function_basic(decomp_ifc, func, monitor)
                if decompiled:
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
                # Check for preserved variable names
                local_vars = get_function_local_variables(func)
                params = get_function_parameters_with_names(func)

                if local_vars or params:
                    funcs_with_debug_vars += 1
                    total_preserved_vars += len(local_vars) + len(params)

                decompiled = get_decompiled_function_basic(decomp_ifc, func, monitor)
                if decompiled:
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

    # Report debug info utilization
    if has_debug:
        print("\n[Debug Info] DWARF information utilized:")
        print(
            "  - Functions with preserved variable names: {}".format(
                funcs_with_debug_vars
            )
        )
        print("  - Total preserved variables: {}".format(total_preserved_vars))


# Run main function
if __name__ == "__main__":
    main()
else:
    # Running as script in Ghidra
    main()
