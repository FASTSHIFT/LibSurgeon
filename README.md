# LibSurgeon 🔬

**Static Library Dissector - Automated Reverse Engineering with Ghidra**

LibSurgeon is a powerful automated tool that performs surgical extraction of C/C++ source code from static library archives (`.a` files). It leverages Ghidra's advanced decompilation engine to reconstruct readable source code from compiled object files.

## Features

- 🔍 **Auto-Discovery**: Automatically scans directories for `.a` archives and header files
- ⚡ **Parallel Processing**: Multi-threaded decompilation with configurable job count
- 📊 **Progress Tracking**: Real-time progress display with ETA estimation
- 📁 **Organized Output**: Clean directory structure with sources, headers, and logs
- 📝 **Documentation**: Auto-generated README and summary reports

## How It Works

### The Decompilation Pipeline

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  .a Archive │ -> │  Extract    │ -> │   Ghidra    │ -> │  .cpp Files │
│   (input)   │    │  .o files   │    │  Decompile  │    │  (output)   │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

1. **Archive Extraction**: Uses `ar` to extract individual object files (`.o`) from the static library
2. **Symbol Analysis**: Ghidra analyzes the ELF format, identifies functions, data structures, and cross-references
3. **Decompilation**: Ghidra's decompiler translates machine code back to C/C++ pseudocode
4. **Output Generation**: Each object file produces a corresponding `.cpp` source file

### Why Static Libraries?

Static libraries (`.a` files) are collections of object files that get linked directly into executables. Unlike dynamically linked libraries, they:
- Contain complete compiled code
- Often preserve symbol names (if not stripped)
- Can be analyzed without runtime dependencies

### Technical Details

- **Target Architecture**: ARM Cortex-M (32-bit Little Endian) by default
- **Decompiler**: Ghidra's native decompiler with full analysis
- **Symbol Preservation**: Original function/variable names retained if not stripped
- **Parallel Safety**: Each object file processed in isolated Ghidra project

## Requirements

- **Ghidra** 11.0 or later (with analyzeHeadless support)
- **Java** 17 or later (required by Ghidra)
- **GNU Binutils** (for `ar` command)
- **Bash** 4.0+ (for array support)
- **Optional**: GNU Parallel (for improved multi-threading)

## Installation

1. Clone or download this repository
2. Ensure scripts are executable:
   ```bash
   chmod +x libsurgeon.sh ghidra_decompile.py
   ```
3. Install Ghidra from https://ghidra-sre.org/

## Usage

### Basic Usage

```bash
./libsurgeon.sh -g /path/to/ghidra <target_directory>
```

### Options

| Option | Description |
|--------|-------------|
| `-g, --ghidra <path>` | Path to Ghidra installation (REQUIRED) |
| `-o, --output <dir>` | Output directory (default: `./libsurgeon_output`) |
| `-j, --jobs <num>` | Number of parallel jobs (default: auto) |
| `-c, --clean` | Clean previous output before processing |
| `-l, --list` | List archive contents without decompiling |
| `-h, --help` | Show help message |

### Examples

```bash
# Basic decompilation
./libsurgeon.sh -g /opt/ghidra ./vendor/libs

# With 8 parallel jobs
./libsurgeon.sh -g /opt/ghidra -j8 ./sdk/lib

# Clean and reprocess
./libsurgeon.sh -g /opt/ghidra --clean -o ./my_output ./third_party

# Just list contents
./libsurgeon.sh -g /opt/ghidra --list ./libs
```

## Output Structure

```
libsurgeon_output/
├── library_name/
│   ├── src/              # Decompiled C/C++ source files
│   │   ├── module1.cpp
│   │   ├── module2.cpp
│   │   └── ...
│   ├── include/          # Copied original headers (if found)
│   │   └── ...
│   ├── logs/             # Ghidra processing logs
│   │   ├── module1_ghidra.log
│   │   └── failed_files.txt
│   └── README.md         # Library-specific documentation
└── SUMMARY.md            # Overall summary report
```

## Understanding the Output

### Decompiled Code Characteristics

The decompiled C/C++ code will have certain characteristics:

```cpp
// Original function names are preserved (if not stripped)
void HAL_Init(void) {
    // Local variables use auto-generated names
    int local_10;
    void *param_1;
    
    // Pointer arithmetic may appear verbose
    *(int *)(param_1 + 0x10) = local_10;
    
    // Virtual calls appear as indirect function pointers
    (**(code **)(*(int *)this + 0x1c))(this);
}
```

### Tips for Analysis

1. **Start with Headers**: Original headers provide class definitions and API documentation
2. **Identify Patterns**: Look for common patterns like vtables, constructors, and destructors
3. **String References**: Search for string literals to understand functionality
4. **Cross-Reference**: Use Ghidra GUI for interactive exploration of complex code

## Customization

### Changing Target Architecture

Edit `libsurgeon.sh` to modify the processor specification:

```bash
# For different ARM variants
-processor "ARM:LE:32:Cortex"     # Cortex-M
-processor "ARM:LE:32:v7"         # ARMv7
-processor "ARM:LE:32:v8"         # ARMv8 (32-bit)

# For other architectures
-processor "x86:LE:32:default"    # x86 32-bit
-processor "x86:LE:64:default"    # x86-64
-processor "MIPS:LE:32:default"   # MIPS 32-bit
```

### Ghidra Script Customization

The `ghidra_decompile.py` script can be modified to:
- Add custom analysis passes
- Filter specific functions
- Apply custom naming conventions
- Export additional metadata

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| "Java not found" | Install Java 17+ and ensure it's in PATH |
| "Ghidra headless not found" | Verify Ghidra path with `-g` option |
| Empty output files | Check logs for analysis errors |
| Memory issues | Reduce parallel jobs with `-j` option |

### Checking Logs

```bash
# View Ghidra log for specific file
cat libsurgeon_output/library/logs/module_ghidra.log

# List failed files
cat libsurgeon_output/library/logs/failed_files.txt
```

## Performance Tips

- **SSD Storage**: Significantly improves I/O-bound operations
- **RAM**: Ghidra can use 2-4GB per instance; adjust `-j` accordingly
- **GNU Parallel**: Install for better job scheduling than bash background processes

## Legal Disclaimer

This tool is intended for:
- Educational purposes and learning
- Security research and vulnerability analysis
- Interoperability and compatibility testing
- Recovery of lost source code (with proper authorization)

**Please respect software licenses and intellectual property rights.**

Reverse engineering may be restricted in some jurisdictions. Ensure compliance with applicable laws and license agreements before use.

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

---

*LibSurgeon - Precision extraction of knowledge from compiled code* 🔬
