#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# flake8: noqa: F821, E722
"""
LibSurgeon - Ghidra Pre-Analysis Script for DWARF Debug Info

This script runs before analysis to configure Ghidra's DWARF analyzer
to import local variable names and other debug information.

This script should be run with -preScript before the main analysis.

Note: Ghidra's DWARF analyzer imports debug info during the import/analysis phase.
The decompiler should then use this information automatically. However, some
DWARF formats (especially from ARM compilers) may not be fully supported.

Note: This script uses Ghidra's Jython environment where 'currentProgram' is
a global variable provided by Ghidra. The bare except clauses are intentional
to handle various Ghidra API exceptions gracefully.
"""


def configure_dwarf_options():
    """Configure DWARF analyzer options for better debug info extraction"""
    print("[DWARF Config] Configuring DWARF analyzer options...")

    try:
        from ghidra.program.model.listing import Program

        # Get analysis options
        options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES)
        option_names = list(options.getOptionNames())

        # Find all DWARF-related options
        dwarf_options = [name for name in option_names if "DWARF" in name.upper()]

        print(f"[DWARF Config] Found {len(dwarf_options)} DWARF-related options")

        # Print all DWARF options for debugging
        for opt in sorted(dwarf_options):
            try:
                val = options.getBoolean(opt, False)
                print(f"  {opt} = {val}")
            except:
                try:
                    val = options.getString(opt, "")
                    print(f"  {opt} = '{val}'")
                except:
                    print(f"  {opt} = <unknown type>")

        # Try to enable key DWARF options
        key_options = [
            "DWARF",  # Main DWARF analyzer
            "DWARF.Import Data Types",
            "DWARF.Import Functions",
            "DWARF.Import Local Variables",
            "DWARF.Output Source Info",
            "DWARF.Create Function Signatures",
        ]

        for opt in key_options:
            if opt in option_names:
                try:
                    options.setBoolean(opt, True)
                    print(f"[DWARF Config] Enabled: {opt}")
                except:
                    pass

        print("[DWARF Config] Configuration complete")

    except Exception as e:
        print(f"[DWARF Config] Warning: {e}")
        import traceback

        traceback.print_exc()


def check_debug_info():
    """Check what debug information was imported"""
    print("\n[DWARF Check] Checking imported debug information...")

    try:
        func_mgr = currentProgram.getFunctionManager()
        functions = list(func_mgr.getFunctions(True))[:5]  # Check first 5 functions

        for func in functions:
            print(f"\n  Function: {func.getName()}")

            # Check parameters
            params = func.getParameters()
            if params:
                print(f"    Parameters ({len(params)}):")
                for p in params:
                    print(f"      - {p.getName()}: {p.getDataType()}")

            # Check local variables
            local_vars = func.getLocalVariables()
            if local_vars:
                print(f"    Local variables ({len(local_vars)}):")
                for v in local_vars[:5]:  # First 5
                    print(f"      - {v.getName()}: {v.getDataType()}")

            # Check if function has source info
            try:
                source_info = func.getComment()
                if source_info:
                    print(f"    Source info: {source_info[:50]}...")
            except:
                pass

    except Exception as e:
        print(f"[DWARF Check] Error: {e}")


def main():
    print("=" * 60)
    print("LibSurgeon - DWARF Configuration Script")
    print("=" * 60)

    configure_dwarf_options()

    # Note: Debug info check happens after analysis, so it won't show much here
    # The actual check should be done in the post-script

    print("\n[DWARF Config] Pre-analysis configuration complete")
    print("[DWARF Config] Debug info will be imported during analysis phase")


# Run main function
if __name__ == "__main__":
    main()
else:
    # Running as script in Ghidra
    main()
