#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LibSurgeon - DWARF Debug Info Parser

Parses DWARF debug information from object files to extract:
- Function names and their original parameter names
- Local variable names
- Type information

This is used as a fallback when Ghidra's DWARF analyzer fails to import
variable names (common with ARMCC-generated DWARF).
"""

import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class DwarfVariable:
    """Represents a variable from DWARF debug info"""

    name: str
    type_name: str = "unknown"
    is_parameter: bool = False
    location: str = ""  # Register or stack location


@dataclass
class DwarfFunction:
    """Represents a function from DWARF debug info"""

    name: str
    return_type: str = "unknown"
    parameters: List[DwarfVariable] = field(default_factory=list)
    local_variables: List[DwarfVariable] = field(default_factory=list)
    low_pc: int = 0
    high_pc: int = 0
    source_file: str = ""
    source_line: int = 0


@dataclass
class DwarfInfo:
    """Complete DWARF information for an object file"""

    functions: Dict[str, DwarfFunction] = field(default_factory=dict)
    source_file: str = ""
    compiler: str = ""
    dwarf_version: int = 0
    has_local_vars: bool = False


def parse_dwarf_info(obj_file: str) -> DwarfInfo:
    """
    Parse DWARF debug information from an object file.

    Args:
        obj_file: Path to the object file

    Returns:
        DwarfInfo object with parsed debug information
    """
    info = DwarfInfo()

    try:
        # Run readelf to get debug info
        result = subprocess.run(
            ["readelf", "--debug-dump=info", obj_file],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode != 0:
            return info

        output = result.stdout
        info = _parse_dwarf_output(output)

    except subprocess.TimeoutExpired:
        pass
    except FileNotFoundError:
        pass
    except Exception:
        pass

    return info


def _parse_dwarf_output(output: str) -> DwarfInfo:
    """Parse the output of readelf --debug-dump=info"""
    info = DwarfInfo()

    lines = output.split("\n")

    # State machine for parsing
    current_function: Optional[DwarfFunction] = None
    in_function = False
    func_depth = 0

    # Type reference map (offset -> type name)
    type_map: Dict[str, str] = {}

    i = 0
    while i < len(lines):
        line = lines[i]

        # Detect depth level - format: " <depth><offset>..."
        # Examples: " <0><b>：", " <1><e5>：", " <2><181>："
        depth_match = re.match(r"\s*<(\d+)><([0-9a-fA-F]+)>", line)
        current_depth = -1
        current_offset = ""
        if depth_match:
            current_depth = int(depth_match.group(1))
            current_offset = depth_match.group(2)

        # Parse compilation unit info
        if "DW_AT_producer" in line:
            match = re.search(r"DW_AT_producer\s*[:：]\s*(.+)$", line)
            if match:
                info.compiler = match.group(1).strip()

        # Parse source file name
        if "DW_AT_name" in line and not in_function:
            match = re.search(r"DW_AT_name\s*[:：]\s*(.+)$", line)
            if match:
                name = match.group(1).strip()
                if name.endswith(".cpp") or name.endswith(".c"):
                    info.source_file = name

        # Parse version from header
        if ("版本" in line or "Version" in line) and "DW_" not in line:
            match = re.search(r"(\d+)", line)
            if match:
                info.dwarf_version = int(match.group(1))

        # Parse base types for type map
        if "DW_TAG_base_type" in line and current_offset:
            # Look for name in next few lines
            for j in range(i + 1, min(i + 6, len(lines))):
                if "DW_AT_name" in lines[j] and "<" not in lines[j][:10]:
                    name_match = re.search(r"DW_AT_name\s*[:：]\s*(.+)$", lines[j])
                    if name_match:
                        type_map[current_offset] = name_match.group(1).strip()
                    break
                if re.match(r"\s*<\d+><", lines[j]):
                    break

        # Parse pointer types
        if "DW_TAG_pointer_type" in line and current_offset:
            for j in range(i + 1, min(i + 4, len(lines))):
                if "DW_AT_type" in lines[j]:
                    ref_match = re.search(r"<0x([0-9a-fA-F]+)>", lines[j])
                    if not ref_match:
                        ref_match = re.search(r"<([0-9a-fA-F]+)>", lines[j])
                    if ref_match:
                        ref_offset = ref_match.group(1)
                        base_type = type_map.get(ref_offset, "void")
                        type_map[current_offset] = base_type + "*"
                    break
                if re.match(r"\s*<\d+><", lines[j]):
                    break

        # Parse subprogram (function)
        if "DW_TAG_subprogram" in line:
            # Save previous function if exists
            if current_function and current_function.name:
                info.functions[current_function.name] = current_function

            current_function = DwarfFunction(name="")
            in_function = True
            func_depth = current_depth

            # Parse function attributes in following lines
            j = i + 1
            while j < len(lines):
                attr_line = lines[j]
                # Stop at next DIE entry
                if re.match(r"\s*<\d+><[0-9a-fA-F]+>", attr_line):
                    break

                if "DW_AT_name" in attr_line:
                    match = re.search(r"DW_AT_name\s*[:：]\s*(\S+)", attr_line)
                    if match:
                        current_function.name = match.group(1).strip()

                elif "DW_AT_low_pc" in attr_line:
                    match = re.search(r"0x([0-9a-fA-F]+)", attr_line)
                    if match:
                        current_function.low_pc = int(match.group(1), 16)

                elif "DW_AT_high_pc" in attr_line:
                    match = re.search(r"0x([0-9a-fA-F]+)", attr_line)
                    if match:
                        current_function.high_pc = int(match.group(1), 16)

                elif "DW_AT_decl_line" in attr_line:
                    match = re.search(r"[:：]\s*(\d+)", attr_line)
                    if match:
                        current_function.source_line = int(match.group(1))

                j += 1

        # Parse formal parameter
        elif "DW_TAG_formal_parameter" in line and current_function and in_function:
            var = DwarfVariable(name="", is_parameter=True)

            j = i + 1
            while j < len(lines):
                attr_line = lines[j]
                if re.match(r"\s*<\d+><[0-9a-fA-F]+>", attr_line):
                    break

                if "DW_AT_name" in attr_line:
                    match = re.search(r"DW_AT_name\s*[:：]\s*(\w+)", attr_line)
                    if match:
                        var.name = match.group(1).strip()

                elif "DW_AT_type" in attr_line:
                    ref_match = re.search(r"<0x([0-9a-fA-F]+)>", attr_line)
                    if not ref_match:
                        ref_match = re.search(r"<([0-9a-fA-F]+)>", attr_line)
                    if ref_match:
                        ref_offset = ref_match.group(1)
                        var.type_name = type_map.get(ref_offset, "unknown")

                elif "DW_AT_location" in attr_line:
                    loc_match = re.search(r"DW_OP_reg\d+\s*\((\w+)\)", attr_line)
                    if loc_match:
                        var.location = loc_match.group(1)

                j += 1

            if var.name and not var.name.startswith("__"):
                current_function.parameters.append(var)
                info.has_local_vars = True

        # Parse local variable
        elif "DW_TAG_variable" in line and current_function and in_function:
            # Check depth - must be inside function (depth > func_depth)
            if current_depth <= func_depth:
                # This is a global variable, not local
                i += 1
                continue

            var = DwarfVariable(name="", is_parameter=False)
            is_artificial = False

            j = i + 1
            while j < len(lines):
                attr_line = lines[j]
                if re.match(r"\s*<\d+><[0-9a-fA-F]+>", attr_line):
                    break

                if "DW_AT_name" in attr_line:
                    match = re.search(r"DW_AT_name\s*[:：]\s*(\w+)", attr_line)
                    if match:
                        var.name = match.group(1).strip()

                elif "DW_AT_type" in attr_line:
                    ref_match = re.search(r"<0x([0-9a-fA-F]+)>", attr_line)
                    if not ref_match:
                        ref_match = re.search(r"<([0-9a-fA-F]+)>", attr_line)
                    if ref_match:
                        ref_offset = ref_match.group(1)
                        var.type_name = type_map.get(ref_offset, "unknown")

                elif "DW_AT_location" in attr_line:
                    loc_match = re.search(r"DW_OP_reg\d+\s*\((\w+)\)", attr_line)
                    if loc_match:
                        var.location = loc_match.group(1)

                elif "DW_AT_artificial" in attr_line:
                    is_artificial = True

                j += 1

            # Skip artificial variables (compiler-generated like __result)
            if var.name and not var.name.startswith("__") and not is_artificial:
                current_function.local_variables.append(var)
                info.has_local_vars = True

        # Check if we're leaving function scope
        if current_depth >= 0 and current_depth <= func_depth and in_function:
            if "DW_TAG_subprogram" not in line:
                # Save current function and reset
                if current_function and current_function.name:
                    info.functions[current_function.name] = current_function
                current_function = None
                in_function = False

        i += 1

    # Save last function
    if current_function and current_function.name:
        info.functions[current_function.name] = current_function

    return info


def generate_variable_comment(func: DwarfFunction) -> str:
    """
    Generate a comment string with original variable names.

    Args:
        func: DwarfFunction with parsed debug info

    Returns:
        Comment string to insert into decompiled code
    """
    parts = []

    if func.parameters:
        param_strs = []
        for p in func.parameters:
            if p.type_name != "unknown":
                param_strs.append(f"{p.type_name} {p.name}")
            else:
                param_strs.append(p.name)
        parts.append(f"Original params: {', '.join(param_strs)}")

    if func.local_variables:
        var_strs = []
        for v in func.local_variables[:8]:  # Limit to 8 vars
            if v.type_name != "unknown":
                var_strs.append(f"{v.type_name} {v.name}")
            else:
                var_strs.append(v.name)
        comment = f"Original locals: {', '.join(var_strs)}"
        if len(func.local_variables) > 8:
            comment += f" + {len(func.local_variables) - 8} more"
        parts.append(comment)

    if not parts:
        return ""

    return "/* " + " | ".join(parts) + " */"


def apply_dwarf_to_code(code: str, dwarf_info: DwarfInfo) -> str:
    """
    Apply DWARF debug information to decompiled code.

    - Substitutes param_N with original parameter names throughout functions
    - Adds comments with original local variable names

    Args:
        code: Decompiled C/C++ code
        dwarf_info: Parsed DWARF information

    Returns:
        Code with enhanced debug info
    """
    if not dwarf_info.functions:
        return code

    # First pass: identify function boundaries and apply substitutions
    lines = code.split("\n")
    result_lines = []

    current_dwarf_func = None
    brace_depth = 0
    in_function_body = False

    i = 0
    while i < len(lines):
        line = lines[i]
        modified_line = line

        # Track brace depth for function body detection
        open_braces = line.count("{")
        close_braces = line.count("}")

        # Look for function definitions
        func_match = re.match(r"^(\w+)\s+(\w+)\s*\(", line.strip())
        if func_match and brace_depth == 0:
            func_name = func_match.group(2)

            if func_name in dwarf_info.functions:
                current_dwarf_func = dwarf_info.functions[func_name]

                # Substitute parameter names in signature
                if current_dwarf_func.parameters:
                    for idx, param in enumerate(current_dwarf_func.parameters):
                        param_pattern = rf"\bparam_{idx + 1}\b"
                        modified_line = re.sub(param_pattern, param.name, modified_line)

        # If we're in a function with DWARF info, substitute param names in body
        if current_dwarf_func and current_dwarf_func.parameters:
            for idx, param in enumerate(current_dwarf_func.parameters):
                param_pattern = rf"\bparam_{idx + 1}\b"
                modified_line = re.sub(param_pattern, param.name, modified_line)

        result_lines.append(modified_line)

        # Update brace depth
        brace_depth += open_braces - close_braces

        # Add comment after opening brace of function
        if current_dwarf_func and "{" in line and not in_function_body:
            in_function_body = True
            # Add locals comment if we have local variables
            if current_dwarf_func.local_variables:
                var_strs = [v.name for v in current_dwarf_func.local_variables[:10]]
                if len(current_dwarf_func.local_variables) > 10:
                    var_strs.append(
                        f"+{len(current_dwarf_func.local_variables) - 10} more"
                    )
                result_lines.append(f"/* Original locals: {', '.join(var_strs)} */")

        # Reset when function ends
        if brace_depth == 0 and in_function_body:
            current_dwarf_func = None
            in_function_body = False

        i += 1

    return "\n".join(result_lines)


def create_variable_mapping(dwarf_info: DwarfInfo) -> Dict[str, Dict[str, str]]:
    """
    Create a mapping for variable name substitution.

    Returns a dict: {function_name: {param_1: original_name, ...}}
    """
    mapping = {}

    for func_name, func in dwarf_info.functions.items():
        func_mapping = {}

        # Map parameters
        for i, param in enumerate(func.parameters):
            auto_name = f"param_{i + 1}"
            func_mapping[auto_name] = param.name

        if func_mapping:
            mapping[func_name] = func_mapping

    return mapping


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: dwarf_parser.py <object_file>")
        sys.exit(1)

    obj_file = sys.argv[1]
    info = parse_dwarf_info(obj_file)

    print(f"Source file: {info.source_file}")
    print(f"Compiler: {info.compiler}")
    print(f"DWARF version: {info.dwarf_version}")
    print(f"Has local vars: {info.has_local_vars}")
    print(f"Functions: {len(info.functions)}")
    print()

    for name, func in list(info.functions.items())[:10]:
        print(f"Function: {name}")
        if func.parameters:
            params = [f"{p.type_name} {p.name}" for p in func.parameters]
            print(f"  Parameters: {', '.join(params)}")
        if func.local_variables:
            vars = [f"{v.type_name} {v.name}" for v in func.local_variables]
            print(f"  Locals: {', '.join(vars)}")
        print()
