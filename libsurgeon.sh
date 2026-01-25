#!/bin/bash
# -*- coding: utf-8 -*-
#
# LibSurgeon - Static Library & ELF Reverse Engineering Tool
# Automated decompilation of .a archive and ELF files to C/C++ source code
#
# Usage:
#   ./libsurgeon.sh [options] <target_directory_or_file>
#
# Options:
#   -g, --ghidra <path>     Path to Ghidra installation (required)
#   -o, --output <dir>      Output directory (default: ./libsurgeon_output)
#   -j, --jobs <num>        Number of parallel jobs (default: auto)
#   -m, --module <strategy> Module grouping strategy for ELF: prefix|alpha|camelcase|single
#   -c, --clean             Clean previous output
#   -l, --list              List archive contents only
#   -h, --help              Show help message
#

# Don't use 'set -e' as it causes issues with grep/wc returning non-zero
# Handle errors explicitly where needed

# ============================================================
# Configuration
# ============================================================

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

# Default configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHIDRA_PATH=""
OUTPUT_DIR="./libsurgeon_output"
TARGET_DIR=""
CLEAN_OUTPUT=false
LIST_ONLY=false

# Module grouping strategy for ELF files
MODULE_STRATEGY="prefix"  # prefix|alpha|camelcase|single

# Supported file types:\n#   Archives (need ar extraction): .a, .lib
#   ELF (direct Ghidra processing): .so, .elf, .axf, .out, .o

# Filter patterns (arrays of glob patterns)
declare -a EXCLUDE_PATTERNS=()
declare -a INCLUDE_PATTERNS=()

# Parallel processing (default: half of CPU cores)
PARALLEL_JOBS=$(( ($(nproc) + 1) / 2 ))
[ "$PARALLEL_JOBS" -lt 1 ] && PARALLEL_JOBS=1
[ "$PARALLEL_JOBS" -gt 16 ] && PARALLEL_JOBS=16

# Ghidra related
GHIDRA_HEADLESS=""
DECOMPILE_SCRIPT="${SCRIPT_DIR}/ghidra_decompile.py"
DECOMPILE_ELF_SCRIPT="${SCRIPT_DIR}/ghidra_decompile_elf.py"

# ============================================================
# Function Definitions
# ============================================================

print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              LibSurgeon - Static Library Dissector           ║"
    echo "║          Automated Reverse Engineering with Ghidra           ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${MAGENTA}[STEP]${NC} $1"
}

# ============================================================
# Box Drawing Functions
# ============================================================

# Draw a box with auto-sized width
# Usage: draw_box "color" "title" ["subtitle"]
draw_box() {
    local color="$1"
    local title="$2"
    local subtitle="${3:-}"
    
    # Calculate required width (minimum 50, add padding)
    local title_len=${#title}
    local subtitle_len=${#subtitle}
    local max_len=$((title_len > subtitle_len ? title_len : subtitle_len))
    local width=$((max_len + 6))  # Add padding
    [[ $width -lt 50 ]] && width=50
    [[ $width -gt 80 ]] && width=80
    
    # Generate horizontal line
    local line=""
    for ((i=0; i<width; i++)); do
        line+="═"
    done
    
    echo -e "${color}╔${line}╗${NC}"
    
    # Center the title
    local padding=$(( (width - title_len) / 2 ))
    local pad_left=""
    local pad_right=""
    for ((i=0; i<padding; i++)); do pad_left+=" "; done
    for ((i=0; i<(width - title_len - padding); i++)); do pad_right+=" "; done
    echo -e "${color}║${pad_left}${title}${pad_right}║${NC}"
    
    # Subtitle if provided
    if [ -n "$subtitle" ]; then
        padding=$(( (width - subtitle_len) / 2 ))
        pad_left=""
        pad_right=""
        for ((i=0; i<padding; i++)); do pad_left+=" "; done
        for ((i=0; i<(width - subtitle_len - padding); i++)); do pad_right+=" "; done
        echo -e "${color}║${pad_left}${subtitle}${pad_right}║${NC}"
    fi
    
    echo -e "${color}╚${line}╝${NC}"
}

# Draw a simple section header
# Usage: draw_section "color" "title"
draw_section() {
    local color="$1"
    local title="$2"
    
    # Calculate width based on title
    local title_len=${#title}
    local width=$((title_len + 10))
    [[ $width -lt 50 ]] && width=50
    [[ $width -gt 80 ]] && width=80
    
    # Generate line
    local line=""
    for ((i=0; i<width; i++)); do
        line+="─"
    done
    
    echo -e "${color}┌${line}┐${NC}"
    
    # Center the title
    local padding=$(( (width - title_len) / 2 ))
    local pad_left=""
    local pad_right=""
    for ((i=0; i<padding; i++)); do pad_left+=" "; done
    for ((i=0; i<(width - title_len - padding); i++)); do pad_right+=" "; done
    echo -e "${color}│${pad_left}${title}${pad_right}│${NC}"
    
    echo -e "${color}└${line}┘${NC}"
}

# ============================================================
# Progress Display Functions
# ============================================================

format_time() {
    local seconds=$1
    if [ "$seconds" -lt 60 ]; then
        echo "${seconds}s"
        elif [ "$seconds" -lt 3600 ]; then
        local mins=$((seconds / 60))
        local secs=$((seconds % 60))
        echo "${mins}m${secs}s"
    else
        local hours=$((seconds / 3600))
        local mins=$(((seconds % 3600) / 60))
        echo "${hours}h${mins}m"
    fi
}

draw_progress_bar() {
    local current=$1
    local total=$2
    local width=40
    local percentage=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))
    
    local bar=""
    for ((i=0; i<filled; i++)); do
        bar+="█"
    done
    for ((i=0; i<empty; i++)); do
        bar+="░"
    done
    
    echo -n "$bar"
}

show_progress() {
    local current=$1
    local total=$2
    local filename=$3
    local elapsed=$4
    local eta=${5:-0}
    
    # Ensure numeric values
    [[ ! "$current" =~ ^[0-9]+$ ]] && current=0
    [[ ! "$total" =~ ^[0-9]+$ ]] && total=1
    [[ ! "$elapsed" =~ ^[0-9]+$ ]] && elapsed=0
    [[ ! "$eta" =~ ^[0-9]+$ ]] && eta=0
    
    local percentage=0
    if [[ $total -gt 0 ]]; then
        percentage=$((current * 100 / total))
    fi
    local bar=$(draw_progress_bar $current $total)
    
    # Clear current line and show progress
    echo -ne "\r\033[K"
    
    # Progress bar line
    echo -ne "${CYAN}[${bar}]${NC} ${BOLD}${percentage}%${NC} (${current}/${total})"
    
    # Time info
    if [[ $eta -gt 0 ]]; then
        echo -ne " | Elapsed: $(format_time $elapsed) | ETA: ${YELLOW}$(format_time $eta)${NC}"
    else
        echo -ne " | Elapsed: $(format_time $elapsed)"
    fi
    
    echo ""
    
    # Current file
    if [[ -n "$filename" ]]; then
        echo -e "${DIM}  -> Completed: ${NC}${GREEN}${filename}${NC}"
    else
        echo -e "${DIM}  -> Processing...${NC}"
    fi
    
    # Move cursor up 2 lines
    echo -ne "\033[2A"
}

show_progress_final() {
    local total=$1
    local elapsed=$2
    
    echo -ne "\r\033[K\n\033[K\n"
    echo -ne "\033[2A"
    
    local bar=$(draw_progress_bar $total $total)
    echo -e "${GREEN}[${bar}]${NC} ${BOLD}100%${NC} (${total}/${total}) | Total: $(format_time $elapsed)"
    echo ""
}

show_help() {
    cat << EOF
Usage: $0 [options] <target_directory_or_file>

LibSurgeon recursively scans the target directory for all supported binary files
and decompiles them using Ghidra. All supported file types are processed in a
single unified pass.

Supported File Types:
  Archives (extract .o then decompile): .a, .lib
  ELF files (direct decompile):         .so, .elf, .axf, .out, .o

Options:
  -g, --ghidra <path>     Path to Ghidra installation (REQUIRED)
  -o, --output <dir>      Output directory (default: ./libsurgeon_output)
  -j, --jobs <num>        Number of parallel jobs (default: $PARALLEL_JOBS)
  -m, --module <strategy> Module grouping strategy for ELF files:
                            prefix    - Group by function prefix (xxBmp*, xxFnt*) [default]
                            alpha     - Group by first letter (A-Z)
                            camelcase - Group by CamelCase words
                            single    - All functions in one file
  -i, --include <pattern> Only include files matching pattern (can be used multiple times)
  -e, --exclude <pattern> Exclude files matching pattern (can be used multiple times)
  -c, --clean             Clean previous output before processing
  -l, --list              List file contents without decompiling
  -h, --help              Show this help message

Filter Rules:
  - Directory scanning is RECURSIVE (searches all subdirectories)
  - Filters apply to ALL supported file types (.a, .lib, .so, .elf, etc.)
  - If --include is specified, only matching files are processed
  - If --exclude is specified, matching files are skipped
  - Patterns support wildcards: * (any chars), ? (single char), [abc] (char set)

Examples:
  # Process ALL supported files in a directory (recursive)
  $0 -g /opt/ghidra ./my_sdk/

  # Process a single file (auto-detect type)
  $0 -g /opt/ghidra ./firmware.elf
  $0 -g /opt/ghidra ./libfoo.a
  $0 -g /opt/ghidra ./libbar.so

  # ELF module grouping strategies
  $0 -g /opt/ghidra -m alpha ./firmware.elf          # Alphabetic grouping
  $0 -g /opt/ghidra -m camelcase ./firmware.axf      # CamelCase word grouping
  $0 -g /opt/ghidra -m single ./app.out              # Single file output

  # Filter files
  $0 -g /opt/ghidra -i "libgre*" ./sdk/              # Only libgre* files
  $0 -g /opt/ghidra -e "*test*" ./vendor/            # Exclude test libraries

  # List contents only (no decompilation)
  $0 -g /opt/ghidra --list ./my_sdk/

Output Structure:
  For .a archives:
    libsurgeon_output/
    ├── <library_name>/
    │   ├── src/           # Decompiled C/C++ source files (one per .o)
    │   ├── include/       # Copied header files (if found)
    │   └── logs/          # Ghidra processing logs
    └── SUMMARY.md         # Overview report

  For ELF files:
    libsurgeon_output/
    ├── <elf_name>/
    │   ├── src/           # Decompiled C/C++ source files (grouped by module)
    │   ├── logs/          # Ghidra processing logs
    │   └── <elf_name>_INDEX.md  # Function index
    └── SUMMARY.md         # Overview report

Module Grouping Strategies for ELF:
  prefix     - Best for libraries with consistent naming (e.g., xxBmp*, GfxCreate*)
               Functions are grouped by their common prefix.
               Example output: firmware_xxBmp.cpp, firmware_xxFnt.cpp

  alpha      - Simple A-Z grouping by first letter
               Useful for very large ELF files as a first pass
               Example output: firmware_A.cpp, firmware_B.cpp, ...

  camelcase  - Extract meaningful words from CamelCase names
               Good for object-oriented code
               Example output: firmware_EwCreate.cpp, firmware_GfxInit.cpp

  single     - All functions in one file
               Use for small ELF files or when module grouping isn't needed
               Example output: firmware_all_functions.cpp

Notes:
  - Ghidra 11+ with Java 17+ is required
  - ARM Cortex-M processor is assumed (can be modified in script)
  - Original symbols are preserved if not stripped
  - For .a files: Each .o file produces one .cpp file
  - For ELF files: Functions are grouped by the selected strategy

EOF
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    if [ -z "$GHIDRA_PATH" ]; then
        log_error "Ghidra path not specified. Use -g or --ghidra option."
        exit 1
    fi
    
    GHIDRA_HEADLESS="${GHIDRA_PATH}/support/analyzeHeadless"
    
    if ! command -v ar &> /dev/null; then
        log_error "'ar' command not found. Please install binutils."
        exit 1
    fi
    
    if [ ! -f "$GHIDRA_HEADLESS" ]; then
        log_error "Ghidra headless tool not found: $GHIDRA_HEADLESS"
        log_error "Please specify correct Ghidra path with -g option."
        exit 1
    fi
    
    if ! command -v java &> /dev/null; then
        log_error "Java not found. Ghidra requires Java 17 or higher."
        exit 1
    fi
    
    JAVA_VERSION=$(java -version 2>&1 | head -n 1 | awk -F '"' '{print $2}' | cut -d'.' -f1)
    if [ "$JAVA_VERSION" -lt 17 ]; then
        log_warn "Java version may be too low ($JAVA_VERSION). Ghidra 11 requires Java 17+."
    fi
    
    if [ ! -f "$DECOMPILE_SCRIPT" ]; then
        log_error "Decompile script not found: $DECOMPILE_SCRIPT"
        exit 1
    fi
    
    if [ ! -f "$DECOMPILE_ELF_SCRIPT" ]; then
        log_error "ELF decompile script not found: $DECOMPILE_ELF_SCRIPT"
        exit 1
    fi
    
    log_info "Dependencies check passed"
}

# ============================================================
# ELF File Processing
# ============================================================

# List symbols in an ELF file
list_elf_contents() {
    local elf_file="$1"
    
    echo -e "\n${BLUE}=== ELF File Information ===${NC}"
    echo -e "File: $elf_file\n"
    
    # Basic file info
    echo -e "${CYAN}File Type:${NC}"
    file "$elf_file"
    echo ""
    
    # Size info
    local size=$(stat -c%s "$elf_file" 2>/dev/null || stat -f%z "$elf_file" 2>/dev/null)
    echo -e "${CYAN}File Size:${NC} $((size / 1024)) KB"
    echo ""
    
    # Section headers
    echo -e "${CYAN}Sections:${NC}"
    if command -v readelf &> /dev/null; then
        readelf -S "$elf_file" 2>/dev/null | head -30
        elif command -v objdump &> /dev/null; then
        objdump -h "$elf_file" 2>/dev/null | head -30
    fi
    echo ""
    
    # Symbol count
    echo -e "${CYAN}Symbol Summary:${NC}"
    if command -v nm &> /dev/null; then
        local total=$(nm "$elf_file" 2>/dev/null | wc -l)
        local funcs=$(nm "$elf_file" 2>/dev/null | grep -E " [Tt] " | wc -l)
        local data=$(nm "$elf_file" 2>/dev/null | grep -E " [DdBbRr] " | wc -l)
        echo "  - Total symbols: $total"
        echo "  - Functions (T/t): $funcs"
        echo "  - Data (D/d/B/b/R/r): $data"
    fi
    echo ""
    
    # Function name preview
    echo -e "${CYAN}Function Names (first 30):${NC}"
    if command -v nm &> /dev/null; then
        nm "$elf_file" 2>/dev/null | grep -E " [Tt] " | awk '{print $3}' | head -30 | nl
    fi
    echo ""
    
    # Prefix analysis
    echo -e "${CYAN}Function Prefix Analysis (for module grouping):${NC}"
    if command -v nm &> /dev/null; then
        nm "$elf_file" 2>/dev/null | grep -E " [Tt] " | awk '{print $3}' | \
        grep -v "^\$" | \
        sed 's/\([A-Z][a-z]*[A-Z][a-z]*\).*/\1/' | \
        sort | uniq -c | sort -rn | head -20
    fi
}

# Process a single ELF file
decompile_elf_file() {
    local elf_file="$1"
    local output_base="$2"
    local strategy="$3"
    
    local elf_name=$(basename "$elf_file")
    elf_name="${elf_name%.*}"  # Remove extension
    
    local elf_output="${output_base}/${elf_name}"
    
    echo ""
    draw_box "${BLUE}" "Processing ELF: ${elf_name}" "Strategy: ${strategy}"
    
    # Validate ELF file
    if [ ! -f "$elf_file" ]; then
        log_error "ELF file not found: $elf_file"
        return 1
    fi
    
    if ! is_elf_file "$elf_file"; then
        log_error "Not a valid ELF file: $elf_file"
        return 1
    fi
    
    log_info "ELF File: $elf_file"
    log_info "Output: $elf_output"
    log_info "Module Strategy: $strategy"
    
    # Create output directories
    mkdir -p "$elf_output"
    mkdir -p "$elf_output/logs"
    
    # Time tracking
    local start_time=$(date +%s)
    
    # Create temp Ghidra project
    local temp_project="/tmp/libsurgeon_elf_$$_$RANDOM"
    mkdir -p "$temp_project"
    
    echo ""
    draw_section "${YELLOW}" "Ghidra Analysis & Decompilation"
    echo ""
    log_info "Running Ghidra analysis..."
    
    # Create a named pipe for progress tracking
    local progress_pipe=$(mktemp -u)
    mkfifo "$progress_pipe"
    
    # Run Ghidra in background, output to pipe
    # Python script will create src/ and include/ subdirectories
    "$GHIDRA_HEADLESS" "$temp_project" "elf_project" \
    -import "$elf_file" \
    -processor "ARM:LE:32:Cortex" \
    -cspec "default" \
    -postScript "$DECOMPILE_ELF_SCRIPT" "$elf_output" "$strategy" \
    -deleteProject \
    -scriptlog "$elf_output/logs/ghidra_script.log" \
    2>&1 | tee "$elf_output/logs/ghidra_main.log" > "$progress_pipe" &
    
    local ghidra_pid=$!
    
    # Parse progress from Ghidra output
    local total=0
    local current=0
    local last_func=""
    local analysis_done=false
    
    while IFS= read -r line; do
        # Check for total count
        if [[ "$line" == *"[PROGRESS_TOTAL]"* ]]; then
            total=$(echo "$line" | sed 's/.*\[PROGRESS_TOTAL\] //')
            analysis_done=true
            echo ""
            draw_section "${CYAN}" "Decompilation Progress (${total} functions)"
            echo ""
            # Check for progress update
            elif [[ "$line" == *"[PROGRESS]"* ]]; then
            # Parse: [PROGRESS] current/total func_name
            local progress_info=$(echo "$line" | sed 's/.*\[PROGRESS\] //')
            current=$(echo "$progress_info" | cut -d'/' -f1)
            local func_name=$(echo "$progress_info" | cut -d' ' -f2-)
            
            if [[ $total -gt 0 ]]; then
                local now=$(date +%s)
                local elapsed=$((now - start_time))
                local eta=0
                if [[ $current -gt 0 ]]; then
                    local avg=$((elapsed * 1000 / current))
                    eta=$(((total - current) * avg / 1000))
                fi
                show_progress $current $total "$func_name" $elapsed $eta
            fi
            # Show analysis phase
            elif [[ "$line" == *"INFO  ANALYZING"* ]] || [[ "$line" == *"Analyzing..."* ]]; then
            if [[ "$analysis_done" == false ]]; then
                echo -ne "\r\033[K${DIM}  Ghidra analyzing...${NC}"
            fi
        fi
    done < "$progress_pipe"
    
    # Wait for Ghidra to complete
    wait $ghidra_pid
    local status=$?
    
    # Cleanup pipe
    rm -f "$progress_pipe"
    
    # Show final progress
    if [[ $total -gt 0 ]]; then
        local end_time=$(date +%s)
        local total_elapsed=$((end_time - start_time))
        show_progress_final $total $total_elapsed
    fi
    
    # Cleanup temp project
    rm -rf "$temp_project"
    
    local end_time=$(date +%s)
    local total_elapsed=$((end_time - start_time))
    
    # Check results
    if [[ $status -ne 0 ]]; then
        log_error "Ghidra processing failed. Check logs at: $elf_output/logs/"
        echo ""
        echo "Last 20 lines of log:"
        tail -20 "$elf_output/logs/ghidra_main.log"
        return 1
    fi
    
    # Move index file if generated (Python script puts it in output_dir, not src)
    if [ -f "$elf_output/_INDEX.md" ]; then
        log_info "Index file already in correct location"
    fi
    
    # Statistics
    local cpp_count=$(find "$elf_output/src" -name "*.cpp" 2>/dev/null | wc -l)
    local h_count=$(find "$elf_output/include" -name "*.h" 2>/dev/null | wc -l)
    local total_lines=$(find "$elf_output/src" -name "*.cpp" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}')
    [[ -z "$total_lines" ]] && total_lines=0
    
    echo ""
    draw_section "${GREEN}" "ELF Processing Complete - ${elf_name}"
    echo -e "  ${GREEN}Status:${NC} Success"
    echo -e "  ${BLUE}Duration:${NC} $(format_time $total_elapsed)"
    echo -e "  ${CYAN}Output Files:${NC}"
    echo -e "     - Source files: $cpp_count .cpp files (in src/)"
    echo -e "     - Header files: $h_count .h files (in include/)"
    echo -e "     - Total lines: $total_lines"
    echo ""
    
    # List generated files (top 10 by size)
    echo -e "  ${CYAN}Generated Modules (top 10 by size):${NC}"
    find "$elf_output/src" -name "*.cpp" -type f -exec wc -l {} + 2>/dev/null | \
    grep -v "total$" | sort -rn | head -10 | while read lines fname; do
        local basename_f=$(basename "$fname")
        echo "     - $basename_f ($lines lines)"
    done
    if [[ $cpp_count -gt 10 ]]; then
        echo -e "     ${DIM}... and $((cpp_count - 10)) more modules${NC}"
    fi
    echo ""
    
    # Generate ELF-specific README
    generate_elf_readme "$elf_name" "$elf_output" "$strategy" "$cpp_count" "$total_elapsed"
    
    return 0
}

generate_elf_readme() {
    local elf_name="$1"
    local elf_output="$2"
    local strategy="$3"
    local module_count="$4"
    local elapsed="$5"
    
    local readme_file="$elf_output/README.md"
    
    cat > "$readme_file" << EOF
# ${elf_name} - Decompiled ELF Output

## Overview
- Source: ${elf_name}.elf
- Generated: $(date '+%Y-%m-%d %H:%M:%S')
- Module Strategy: ${strategy}
- Output Modules: ${module_count}
- Processing time: $(format_time $elapsed)

## Module Grouping Strategy: ${strategy}

EOF
    
    case "$strategy" in
        prefix)
            cat >> "$readme_file" << 'EOF'
Functions are grouped by their naming prefix. This works best for libraries
with consistent naming conventions like:
- xxBmp* (Bitmap functions) -> elf_name_xxBmp.cpp
- xxFnt* (Font functions) -> elf_name_xxFnt.cpp
- GfxCreate* (Graphics creation) -> elf_name_GfxCreate.cpp
EOF
        ;;
        alpha)
            cat >> "$readme_file" << 'EOF'
Functions are grouped alphabetically (A-Z). This is useful for very large
ELF files as a first-pass organization:
- A* functions -> elf_name_A.cpp
- B* functions -> elf_name_B.cpp
EOF
        ;;
        camelcase)
            cat >> "$readme_file" << 'EOF'
Functions are grouped by extracting CamelCase words from their names:
- EwCreateBitmap, EwCreateSurface -> elf_name_EwCreate.cpp
- GfxInitViewport, GfxInitGfx -> elf_name_GfxInit.cpp
EOF
        ;;
        single)
            cat >> "$readme_file" << 'EOF'
All functions are placed in a single output file. Useful for small ELF files
or when no grouping is desired.
EOF
        ;;
    esac
    
    cat >> "$readme_file" << EOF

## Directory Structure
\`\`\`
${elf_name}/
├── src/              # Decompiled source code (.cpp files)
├── include/          # Header files (.h files)
│   ├── _types.h      # Type definitions (structures, enums, typedefs)
│   └── _all_headers.h # Master header including all module headers
├── logs/             # Ghidra processing logs
├── _INDEX.md         # Complete function index
└── README.md         # This file
\`\`\`

## Source Files
EOF
    
    echo -e "\n### Decompiled Modules (src/)\n" >> "$readme_file"
    
    find "$elf_output/src" -name "*.cpp" -type f | sort | while read f; do
        local fname=$(basename "$f")
        local lines=$(wc -l < "$f")
        local funcs=$(grep -c "^// Function:" "$f" 2>/dev/null || echo 0)
        echo "- \`$fname\` - $funcs functions ($lines lines)" >> "$readme_file"
    done
    
    echo -e "\n### Header Files (include/)\n" >> "$readme_file"
    
    find "$elf_output/include" -name "*.h" -type f | sort | while read f; do
        local fname=$(basename "$f")
        local lines=$(wc -l < "$f")
        echo "- \`$fname\` ($lines lines)" >> "$readme_file"
    done
    
    cat >> "$readme_file" << 'EOF'

## Usage Notes

1. **Module Organization**: Each .cpp file contains related functions based on the grouping strategy
2. **Index File**: See the *_INDEX.md file for a complete function listing with addresses
3. **Check Logs**: The logs/ directory contains Ghidra processing logs for troubleshooting

## Understanding the Output

- Function addresses are preserved in comments for cross-referencing
- Mangled C++ names (if any) are shown alongside demangled versions
- Auto-generated variable names (param_1, local_10) are from Ghidra analysis

## Disclaimer

- Decompiled code is for educational and research purposes only
- Variable and some function names are auto-inferred by Ghidra
- Code may not compile directly without modifications
- Please respect software licenses and intellectual property rights
EOF
}

# ============================================================
# Unified File Scanning and Type Detection
# ============================================================

# Get file type based on extension
# Returns: archive, elf, or unknown
get_file_type() {
    local file="$1"
    local basename=$(basename "$file")
    local ext=""
    
    # Handle .so.* pattern (e.g., libfoo.so.1.2.3)
    if [[ "$basename" == *.so.* ]]; then
        ext="so"
    else
        # Get extension (lowercase)
        ext="${basename##*.}"
        ext="${ext,,}"  # Convert to lowercase
    fi
    
    # Determine type based on extension (avoid associative array issues)
    case "$ext" in
        a|lib)
            echo "archive"
            ;;
        so|elf|axf|out|o)
            echo "elf"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# Scan directory for all supported files recursively
# Outputs files as they are found (for real-time display)
scan_all_files() {
    local dir="$1"
    
    # Find all supported file types
    # Archives: .a, .lib
    # ELF: .so, .so.*, .elf, .axf, .out, .o
    find "$dir" \( \
        -name "*.a" -o \
        -name "*.lib" -o \
        -name "*.so" -o \
        -name "*.so.*" -o \
        -name "*.elf" -o \
        -name "*.axf" -o \
        -name "*.out" -o \
        -name "*.o" \
    \) -type f 2>/dev/null
}

# Scan with real-time display and timing
scan_with_progress() {
    local dir="$1"
    local scan_start=$(date +%s)
    local file_count=0
    local archive_count=0
    local elf_count=0
    
    echo ""
    draw_section "${CYAN}" "Scanning Directory: ${dir}"
    echo ""
    echo -e "${DIM}Supported: .a .lib .so .elf .axf .out .o${NC}"
    echo ""
    
    # Create temp file to store results
    local temp_file=$(mktemp)
    
    # Scan and display in real-time
    while IFS= read -r file; do
        ((file_count++))
        echo "$file" >> "$temp_file"
        
        # Get file type for display
        local ftype=$(get_file_type "$file")
        local type_label=""
        case "$ftype" in
            archive) 
                ((archive_count++))
                type_label="${YELLOW}[ARCHIVE]${NC}"
                ;;
            elf)
                ((elf_count++))
                type_label="${CYAN}[ELF]${NC}"
                ;;
            *)
                type_label="${DIM}[???]${NC}"
                ;;
        esac
        
        # Calculate elapsed time
        local now=$(date +%s)
        local elapsed=$((now - scan_start))
        
        # Display found file with relative path
        local rel_path="${file#$dir/}"
        if [ "$rel_path" = "$file" ]; then
            rel_path=$(basename "$file")
        fi
        
        # Update display
        echo -e "  ${GREEN}[$file_count]${NC} $type_label $rel_path"
        
    done < <(scan_all_files "$dir")
    
    # Final timing
    local scan_end=$(date +%s)
    local total_elapsed=$((scan_end - scan_start))
    
    echo ""
    echo -e "${GREEN}─── Scan Complete ───${NC}"
    echo -e "  ${BOLD}Total files:${NC} $file_count"
    echo -e "  ${YELLOW}Archives (.a/.lib):${NC} $archive_count"
    echo -e "  ${CYAN}ELF files (.so/.elf/.o):${NC} $elf_count"
    echo -e "  ${BLUE}Scan time:${NC} $(format_time $total_elapsed)"
    echo ""
    
    # Output sorted results
    sort "$temp_file"
    rm -f "$temp_file"
}

# Check if file is a valid ELF (by magic number)
# Follows symlinks and checks real file
is_elf_file() {
    local file="$1"
    
    # Follow symlinks to get the real file
    if [ -L "$file" ]; then
        file=$(readlink -f "$file" 2>/dev/null) || return 1
    fi
    
    # Check file exists and is readable
    if [ ! -f "$file" ] || [ ! -r "$file" ]; then
        return 1
    fi
    
    # Check file size (ELF header is at least 16 bytes)
    local size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo 0)
    if [ "$size" -lt 16 ]; then
        return 1
    fi
    
    # Check ELF magic number (0x7F 'E' 'L' 'F')
    local magic=$(head -c 4 "$file" 2>/dev/null | od -A n -t x1 2>/dev/null | tr -d ' \n')
    if [[ "$magic" == "7f454c46" ]]; then
        return 0
    fi
    return 1
}

# Check if archive should be excluded based on patterns
should_exclude() {
    local archive="$1"
    local basename=$(basename "$archive")
    
    for pattern in "${EXCLUDE_PATTERNS[@]}"; do
        # Use bash pattern matching
        if [[ "$basename" == $pattern ]]; then
            return 0  # Should exclude
        fi
    done
    return 1  # Should not exclude
}

# Check if archive matches include patterns
matches_include() {
    local archive="$1"
    local basename=$(basename "$archive")
    
    # If no include patterns, everything matches
    if [ ${#INCLUDE_PATTERNS[@]} -eq 0 ]; then
        return 0
    fi
    
    for pattern in "${INCLUDE_PATTERNS[@]}"; do
        if [[ "$basename" == $pattern ]]; then
            return 0  # Matches
        fi
    done
    return 1  # Does not match
}

# Filter archives based on include/exclude patterns
filter_archives() {
    local -n archives_ref=$1
    local filtered=()
    local included_count=0
    local excluded_count=0
    
    for archive in "${archives_ref[@]}"; do
        local basename=$(basename "$archive")
        
        # First check include patterns
        if ! matches_include "$archive"; then
            log_warn "Skipping (not in include list): $basename"
            ((excluded_count++))
            continue
        fi
        
        # Then check exclude patterns
        if should_exclude "$archive"; then
            log_warn "Excluding: $basename"
            ((excluded_count++))
            continue
        fi
        
        filtered+=("$archive")
        ((included_count++))
    done
    
    if [[ $excluded_count -gt 0 ]]; then
        log_info "Filtered: $included_count included, $excluded_count excluded"
    fi
    
    archives_ref=("${filtered[@]}")
}

# Find include directory associated with a specific .a file
# Strategy: Look for 'include' directory as sibling or ancestor of the .a file
find_library_headers() {
    local archive_path="$1"
    local archive_dir=$(dirname "$archive_path")
    local found_includes=()
    
    # Strategy 1: Look for 'include' as sibling directory
    # e.g., lib/foo.a -> include/
    local parent_dir=$(dirname "$archive_dir")
    while [ "$parent_dir" != "/" ] && [ "$parent_dir" != "." ]; do
        local include_candidate="$parent_dir/include"
        if [ -d "$include_candidate" ]; then
            # Verify it contains headers
            if find "$include_candidate" \( -name "*.h" -o -name "*.hpp" \) -type f | head -1 | grep -q .; then
                found_includes+=("$include_candidate")
                break
            fi
        fi
        parent_dir=$(dirname "$parent_dir")
    done
    
    # Strategy 2: Look for include directory at same level as lib directory
    # e.g., component/lib/foo.a -> component/include/
    local lib_parent=$(dirname "$archive_dir")
    if [[ "$archive_dir" == *"/lib"* ]]; then
        # Navigate up to find the component root
        local component_root="$archive_dir"
        while [[ "$component_root" == *"/lib"* ]] && [[ "$(basename "$component_root")" != "lib" ]]; do
            component_root=$(dirname "$component_root")
        done
        component_root=$(dirname "$component_root")
        
        local include_candidate="$component_root/include"
        if [ -d "$include_candidate" ]; then
            if find "$include_candidate" \( -name "*.h" -o -name "*.hpp" \) -type f | head -1 | grep -q .; then
                # Check if not already added
                local already_added=false
                for inc in "${found_includes[@]}"; do
                    if [ "$inc" = "$include_candidate" ]; then
                        already_added=true
                        break
                    fi
                done
                if [ "$already_added" = false ]; then
                    found_includes+=("$include_candidate")
                fi
            fi
        fi
    fi
    
    # Return unique directories
    printf '%s\n' "${found_includes[@]}" | sort -u
}

extract_objects() {
    local archive="$1"
    local extract_dir="$2"
    
    log_info "Extracting objects from $(basename "$archive")..."
    
    mkdir -p "$extract_dir"
    cd "$extract_dir"
    ar -x "$archive"
    
    local count=$(ls -1 *.o 2>/dev/null | wc -l)
    log_info "Extracted $count object files"
    
    cd - > /dev/null
}

list_archive_contents() {
    local archive="$1"
    
    echo -e "\n${BLUE}=== Archive Contents ===${NC}"
    echo -e "File: $archive\n"
    
    ar -t "$archive" | nl
    
    echo -e "\nTotal: $(ar -t "$archive" | wc -l) object files"
}

copy_headers() {
    local include_src="$1"
    local include_dst="$2"
    
    if [ -d "$include_src" ]; then
        log_info "Copying headers: $include_src -> $include_dst"
        mkdir -p "$include_dst"
        cp -r "$include_src"/* "$include_dst"/ 2>/dev/null || true
        
        local header_count=$(find "$include_dst" -name "*.h" -o -name "*.hpp" 2>/dev/null | wc -l)
        log_info "Copied $header_count header files"
    fi
}

decompile_single_object() {
    local obj_file="$1"
    local output_dir="$2"
    local log_dir="$3"
    local obj_name=$(basename "$obj_file" .o)
    
    local file_start_time=$(date +%s)
    
    # Create temp Ghidra project for each .o file
    local temp_project="/tmp/libsurgeon_temp_${obj_name}_$$_$RANDOM"
    mkdir -p "$temp_project"
    
    # Run Ghidra headless analysis and decompilation
    "$GHIDRA_HEADLESS" "$temp_project" "temp_project" \
    -import "$obj_file" \
    -processor "ARM:LE:32:Cortex" \
    -cspec "default" \
    -postScript "$DECOMPILE_SCRIPT" "$output_dir" \
    -deleteProject \
    -scriptlog "$log_dir/${obj_name}_script.log" \
    > "$log_dir/${obj_name}_ghidra.log" 2>&1
    
    local status=$?
    
    # Cleanup temp project
    rm -rf "$temp_project"
    
    local file_end_time=$(date +%s)
    local file_duration=$((file_end_time - file_start_time))
    
    echo "$file_duration"
    return $status
}

# Worker function for parallel processing
decompile_worker() {
    local obj_file="$1"
    local output_dir="$2"
    local log_dir="$3"
    local progress_file="$4"
    local obj_name=$(basename "$obj_file" .o)
    
    # Execute decompilation
    decompile_single_object "$obj_file" "$output_dir" "$log_dir" > /dev/null 2>&1
    local status=$?
    
    # Rename output file
    local decompiled_file="$output_dir/${obj_name}_decompiled.cpp"
    local final_file="$output_dir/${obj_name}.cpp"
    if [ -f "$decompiled_file" ]; then
        mv "$decompiled_file" "$final_file"
    fi
    
    # Update progress (atomic write)
    if [[ $status -eq 0 ]] && [[ -f "$final_file" ]]; then
        echo "OK:${obj_name}" >> "$progress_file"
    else
        echo "FAIL:${obj_name}" >> "$progress_file"
    fi
    
    return $status
}

# Export functions for parallel
export -f decompile_single_object
export -f decompile_worker

# Main decompilation function
decompile_library() {
    local lib_name="$1"
    local archive_file="$2"
    local output_base="$3"
    
    local lib_output="${output_base}/${lib_name}"
    
    echo ""
    draw_box "${BLUE}" "Processing: ${lib_name}"
    
    # Validate archive file
    if [ ! -f "$archive_file" ]; then
        log_error "Archive not found: $archive_file"
        return 1
    fi
    
    log_info "Archive: $archive_file"
    log_info "Output: $lib_output"
    
    # Create output directories
    mkdir -p "$lib_output/src"
    mkdir -p "$lib_output/logs"
    mkdir -p "$lib_output/include"
    
    # Find and copy header files associated with this specific library
    local include_dirs=$(find_library_headers "$archive_file")
    if [ -n "$include_dirs" ]; then
        log_info "Found associated include directories:"
        echo "$include_dirs" | while IFS= read -r inc_dir; do
            echo "  - $inc_dir"
            if [ -d "$inc_dir" ]; then
                copy_headers "$inc_dir" "$lib_output/include"
            fi
        done
    else
        log_warn "No associated include directory found for this library"
    fi
    
    # Create temp directory for extraction
    local extract_dir=$(mktemp -d)
    extract_objects "$archive_file" "$extract_dir"
    
    # Get all .o files
    local obj_files=("$extract_dir"/*.o)
    local total=${#obj_files[@]}
    
    log_info "Total files to process: $total"
    log_info "Using $PARALLEL_JOBS parallel jobs"
    
    # Time tracking
    local start_time=$(date +%s)
    
    # Create progress tracking file
    local progress_file=$(mktemp)
    
    echo ""
    draw_section "${YELLOW}" "Decompilation Progress - ${lib_name} (${PARALLEL_JOBS} threads)"
    echo ""
    
    # Export required variables
    export GHIDRA_HEADLESS DECOMPILE_SCRIPT
    
    # Check for GNU parallel
    if command -v parallel &> /dev/null && [ "$PARALLEL_JOBS" -gt 1 ]; then
        log_info "Using GNU parallel for multi-threaded processing..."
        
        printf '%s\n' "${obj_files[@]}" | \
        parallel -j "$PARALLEL_JOBS" --bar --eta \
        "decompile_worker {} '$lib_output/src' '$lib_output/logs' '$progress_file'"
    else
        # Use bash background processes
        log_info "Using bash background processes..."
        
        local running=0
        local completed=0
        local last_completed_file=""
        local prev_count=0
        
        declare -a bg_pids=()
        
        for obj_file in "${obj_files[@]}"; do
            # Wait for free slot
            while [[ $running -ge $PARALLEL_JOBS ]]; do
                local new_pids=()
                for pid in "${bg_pids[@]}"; do
                    if kill -0 "$pid" 2>/dev/null; then
                        new_pids+=("$pid")
                    else
                        wait "$pid" 2>/dev/null || true
                        running=$((running - 1))
                    fi
                done
                bg_pids=("${new_pids[@]}")
                
                completed=$(wc -l < "$progress_file" 2>/dev/null || echo 0)
                
                if [[ "$completed" -gt "$prev_count" ]]; then
                    last_completed_file=$(tail -1 "$progress_file" 2>/dev/null | cut -d: -f2)
                    prev_count=$completed
                fi
                
                local now=$(date +%s)
                local elapsed=$((now - start_time))
                local eta=0
                if [[ $completed -gt 0 ]]; then
                    local avg=$((elapsed / completed))
                    eta=$(((total - completed) * avg))
                fi
                show_progress $completed $total "$last_completed_file" $elapsed $eta
                
                sleep 0.3
            done
            
            # Start new background task
            decompile_worker "$obj_file" "$lib_output/src" "$lib_output/logs" "$progress_file" &
            bg_pids+=($!)
            running=$((running + 1))
        done
        
        # Wait for all tasks to complete
        while [[ $running -gt 0 ]]; do
            local new_pids=()
            for pid in "${bg_pids[@]}"; do
                if kill -0 "$pid" 2>/dev/null; then
                    new_pids+=("$pid")
                else
                    wait "$pid" 2>/dev/null || true
                    running=$((running - 1))
                fi
            done
            bg_pids=("${new_pids[@]}")
            
            completed=$(wc -l < "$progress_file" 2>/dev/null || echo 0)
            
            if [[ "$completed" -gt "$prev_count" ]]; then
                last_completed_file=$(tail -1 "$progress_file" 2>/dev/null | cut -d: -f2)
                prev_count=$completed
            fi
            
            local now=$(date +%s)
            local elapsed=$((now - start_time))
            local eta=0
            if [[ $completed -gt 0 ]]; then
                local avg=$((elapsed / completed))
                eta=$(((total - completed) * avg))
            fi
            show_progress $completed $total "$last_completed_file" $elapsed $eta
            
            sleep 0.3
        done
    fi
    
    # Newline after progress
    echo ""
    
    # Show final progress
    local end_time=$(date +%s)
    local total_elapsed=$((end_time - start_time))
    
    show_progress_final $total $total_elapsed
    
    # Statistics - use tr to remove any whitespace
    local success_count=$(grep -c "^OK:" "$progress_file" 2>/dev/null | tr -d '[:space:]')
    local fail_count=$(grep -c "^FAIL:" "$progress_file" 2>/dev/null | tr -d '[:space:]')
    [[ -z "$success_count" ]] && success_count=0
    [[ -z "$fail_count" ]] && fail_count=0
    
    # Record failed files
    grep "^FAIL:" "$progress_file" 2>/dev/null | cut -d: -f2 > "$lib_output/logs/failed_files.txt"
    
    # Cleanup
    rm -f "$progress_file"
    rm -rf "$extract_dir"
    
    # Display statistics
    echo ""
    draw_section "${YELLOW}" "Statistics - ${lib_name}"
    echo -e "  ${GREEN}Success:${NC} $success_count files"
    if [[ $fail_count -gt 0 ]]; then
        echo -e "  ${RED}Failed:${NC} $fail_count files (see logs/failed_files.txt)"
    fi
    echo -e "  ${BLUE}Duration:${NC} $(format_time $total_elapsed)"
    if [[ $total -gt 0 ]] && [[ $total_elapsed -gt 0 ]]; then
        local avg_time=$((total_elapsed / total))
        echo -e "  ${BLUE}Average:${NC} $(format_time $avg_time)/file (with parallelization)"
    fi
    
    # Output statistics
    local cpp_count=$(find "$lib_output/src" -name "*.cpp" 2>/dev/null | wc -l)
    local header_count=$(find "$lib_output/include" -name "*.h" -o -name "*.hpp" 2>/dev/null | wc -l)
    echo ""
    echo -e "  ${CYAN}Output Files:${NC}"
    echo -e "     - Decompiled sources: $cpp_count .cpp files"
    echo -e "     - Headers: $header_count files"
    echo ""
    
    # Generate library README
    generate_library_readme "$lib_name" "$lib_output" "$success_count" "$fail_count" "$total_elapsed"
    
    return 0
}

generate_library_readme() {
    local lib_name="$1"
    local lib_output="$2"
    local success_count="$3"
    local fail_count="$4"
    local elapsed="$5"
    
    local readme_file="$lib_output/README.md"
    
    cat > "$readme_file" << EOF
# ${lib_name} - Decompiled Output

## Overview
- Generated: $(date '+%Y-%m-%d %H:%M:%S')
- Successfully processed: ${success_count} files
- Failed: ${fail_count} files
- Processing time: $(format_time $elapsed)

## Directory Structure
\`\`\`
${lib_name}/
├── src/              # Decompiled source code (one .cpp per .o)
├── include/          # Original header files
├── logs/             # Processing logs
└── README.md         # This file
\`\`\`

## Source Files
EOF
    
    echo -e "\n### Decompiled .cpp Files\n" >> "$readme_file"
    
    find "$lib_output/src" -name "*.cpp" -type f | sort | while read f; do
        local fname=$(basename "$f")
        local lines=$(wc -l < "$f")
        echo "- \`$fname\` ($lines lines)" >> "$readme_file"
    done
    
    cat >> "$readme_file" << 'EOF'

## Usage Notes

1. **Reading Code**: Each .cpp file corresponds to one compilation unit from the original library
2. **Reference Headers**: The include/ directory contains original headers for understanding class structures
3. **Check Logs**: The logs/ directory contains Ghidra processing logs for troubleshooting

## Disclaimer

- Decompiled code is for educational and research purposes only
- Variable and some function names are auto-inferred by Ghidra
- Code may not compile directly without modifications
- Please respect software licenses and intellectual property rights
EOF
}

generate_global_summary() {
    local output_dir="$1"
    local summary_file="$output_dir/SUMMARY.md"
    
    log_info "Generating summary report..."
    
    cat > "$summary_file" << EOF
# LibSurgeon - Decompilation Summary

## Generation Info
- Generated: $(date '+%Y-%m-%d %H:%M:%S')
- Output Directory: $output_dir
- Tool: LibSurgeon (Ghidra-based static library decompiler)

## Processed Libraries

EOF
    
    # List all processed libraries
    for lib_dir in "$output_dir"/*/; do
        if [ -d "$lib_dir" ]; then
            local lib_name=$(basename "$lib_dir")
            local cpp_count=$(find "$lib_dir/src" -name "*.cpp" 2>/dev/null | wc -l)
            local header_count=$(find "$lib_dir/include" -name "*.h" -o -name "*.hpp" 2>/dev/null | wc -l)
            
            echo "### ${lib_name}" >> "$summary_file"
            echo "- Decompiled sources: ${cpp_count} files" >> "$summary_file"
            echo "- Header files: ${header_count} files" >> "$summary_file"
            echo "- Location: \`${lib_name}/\`" >> "$summary_file"
            echo "" >> "$summary_file"
        fi
    done
    
    cat >> "$summary_file" << 'EOF'
## Output Structure

```
libsurgeon_output/
├── <library_1>/
│   ├── src/           # Decompiled C/C++ source
│   ├── include/       # Original headers
│   └── logs/          # Processing logs
├── <library_2>/
│   └── ...
└── SUMMARY.md         # This summary file
```

## Tips for Code Analysis

### Understanding Decompiled Code
- Function names are preserved if the library was not stripped
- Local variable names are auto-generated (e.g., `local_10`, `param_1`)
- Class methods typically include `this` pointer as first parameter
- Virtual function tables are represented as function pointer arrays

### Best Practices
1. Start with header files to understand the API design
2. Cross-reference decompiled code with headers
3. Look for string literals to identify functionality
4. Use the logs to debug any decompilation issues

## Legal Notice

This output is for educational and research purposes only.
Please respect software licenses and intellectual property rights.
EOF
    
    log_info "Summary report generated: $summary_file"
}

cleanup() {
    rm -rf "/tmp/libsurgeon_temp_"* 2>/dev/null
}

# ============================================================
# Main Program
# ============================================================

main() {
    print_banner
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -g|--ghidra)
                GHIDRA_PATH="$2"
                shift 2
            ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
            ;;
            -j|--jobs)
                PARALLEL_JOBS="$2"
                shift 2
            ;;
            -j*)
                PARALLEL_JOBS="${1#-j}"
                shift
            ;;
            -m|--module)
                MODULE_STRATEGY="$2"
                shift 2
            ;;
            -i|--include)
                INCLUDE_PATTERNS+=("$2")
                shift 2
            ;;
            -e|--exclude)
                EXCLUDE_PATTERNS+=("$2")
                shift 2
            ;;
            -c|--clean)
                CLEAN_OUTPUT=true
                shift
            ;;
            -l|--list)
                LIST_ONLY=true
                shift
            ;;
            -h|--help)
                show_help
                exit 0
            ;;
            -*)
                log_error "Unknown option: $1"
                show_help
                exit 1
            ;;
            *)
                TARGET_DIR="$1"
                shift
            ;;
        esac
    done
    
    # Validate module strategy
    case "$MODULE_STRATEGY" in
        prefix|alpha|camelcase|single)
            # Valid strategy
        ;;
        *)
            log_error "Invalid module strategy: $MODULE_STRATEGY"
            log_error "Valid strategies: prefix, alpha, camelcase, single"
            exit 1
        ;;
    esac
    
    # Validate target
    if [ -z "$TARGET_DIR" ]; then
        log_error "Target directory or file not specified."
        show_help
        exit 1
    fi
    
    # ============================================================
    # Unified Processing Logic
    # ============================================================
    
    local SINGLE_FILE_MODE=false
    local SINGLE_FILE=""
    local SINGLE_FILE_TYPE=""
    
    # Check if target is a single file or directory
    if [ -f "$TARGET_DIR" ]; then
        SINGLE_FILE=$(realpath "$TARGET_DIR")
        SINGLE_FILE_TYPE=$(get_file_type "$SINGLE_FILE")
        
        if [ "$SINGLE_FILE_TYPE" = "unknown" ]; then
            # Try ELF magic detection for files without recognized extension
            if is_elf_file "$SINGLE_FILE"; then
                SINGLE_FILE_TYPE="elf"
            else
                log_error "Unsupported file type: $TARGET_DIR"
                log_error "Supported: .a .lib .so .elf .axf .out .o"
                exit 1
            fi
        fi
        
        SINGLE_FILE_MODE=true
        log_info "Single file mode: $SINGLE_FILE (type: $SINGLE_FILE_TYPE)"
        
    elif [ ! -d "$TARGET_DIR" ]; then
        log_error "Target does not exist: $TARGET_DIR"
        exit 1
    else
        TARGET_DIR=$(realpath "$TARGET_DIR")
    fi
    
    # Check dependencies
    check_dependencies
    
    # Clean output
    if [ "$CLEAN_OUTPUT" = true ] && [ -d "$OUTPUT_DIR" ]; then
        log_warn "Cleaning output directory: $OUTPUT_DIR"
        rm -rf "$OUTPUT_DIR"
    fi
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_DIR=$(realpath "$OUTPUT_DIR")
    
    # Setup cleanup trap
    trap "cleanup" EXIT
    
    # ============================================================
    # Single File Processing
    # ============================================================
    if [ "$SINGLE_FILE_MODE" = true ]; then
        if [ "$LIST_ONLY" = true ]; then
            if [ "$SINGLE_FILE_TYPE" = "archive" ]; then
                list_archive_contents "$SINGLE_FILE"
            else
                list_elf_contents "$SINGLE_FILE"
            fi
            exit 0
        fi
        
        if [ "$SINGLE_FILE_TYPE" = "archive" ]; then
            local lib_name=$(basename "$SINGLE_FILE")
            lib_name="${lib_name%.a}"
            lib_name="${lib_name%.lib}"
            lib_name=${lib_name#lib}
            decompile_library "$lib_name" "$SINGLE_FILE" "$OUTPUT_DIR"
        else
            decompile_elf_file "$SINGLE_FILE" "$OUTPUT_DIR" "$MODULE_STRATEGY"
        fi
        
        # Generate global summary
        generate_global_summary "$OUTPUT_DIR"
        
        echo ""
        echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
        log_info "Reverse engineering complete!"
        echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
        echo ""
        echo "Output directory: $OUTPUT_DIR"
        echo ""
        exit 0
    fi
    
    # ============================================================
    # Directory Processing - Scan all supported files
    # ============================================================
    
    # Scan with real-time progress display
    mapfile -t ALL_FILES < <(scan_with_progress "$TARGET_DIR")
    
    if [ ${#ALL_FILES[@]} -eq 0 ]; then
        log_error "No supported files found in $TARGET_DIR"
        log_error "Supported extensions: a, lib, so, elf, axf, out, o"
        exit 1
    fi
    
    # Apply include/exclude filters
    if [ ${#INCLUDE_PATTERNS[@]} -gt 0 ] || [ ${#EXCLUDE_PATTERNS[@]} -gt 0 ]; then
        if [ ${#INCLUDE_PATTERNS[@]} -gt 0 ]; then
            log_info "Include filters: ${INCLUDE_PATTERNS[*]}"
        fi
        if [ ${#EXCLUDE_PATTERNS[@]} -gt 0 ]; then
            log_info "Exclude filters: ${EXCLUDE_PATTERNS[*]}"
        fi
        filter_archives ALL_FILES
    fi
    
    if [ ${#ALL_FILES[@]} -eq 0 ]; then
        log_error "No files left after filtering"
        exit 1
    fi
    
    # Categorize files by type
    declare -a ARCHIVE_FILES=()
    declare -a ELF_FILES=()
    declare -a SKIPPED_FILES=()
    
    for file in "${ALL_FILES[@]}"; do
        local ftype=$(get_file_type "$file")
        case "$ftype" in
            archive)
                ARCHIVE_FILES+=("$file")
                ;;
            elf)
                # Verify it's actually a valid ELF file
                if is_elf_file "$file"; then
                    ELF_FILES+=("$file")
                else
                    # Provide more diagnostic info
                    local skip_reason=""
                    if [ -L "$file" ]; then
                        local target=$(readlink -f "$file" 2>/dev/null)
                        if [ ! -e "$target" ]; then
                            skip_reason="broken symlink -> $target"
                        else
                            skip_reason="symlink, target not ELF"
                        fi
                    elif [ ! -r "$file" ]; then
                        skip_reason="not readable"
                    else
                        local size=$(stat -c%s "$file" 2>/dev/null || echo 0)
                        if [ "$size" -lt 16 ]; then
                            skip_reason="too small (${size} bytes)"
                        else
                            skip_reason="no ELF magic header"
                        fi
                    fi
                    log_warn "Skipping: $(basename "$file") ($skip_reason)"
                    SKIPPED_FILES+=("$file")
                fi
                ;;
        esac
    done
    
    log_info "Found ${#ARCHIVE_FILES[@]} archive(s) and ${#ELF_FILES[@]} ELF file(s)"
    
    # Show files to process
    if [ ${#ARCHIVE_FILES[@]} -gt 0 ]; then
        echo -e "${CYAN}Archives (.a/.lib):${NC}"
        for f in "${ARCHIVE_FILES[@]}"; do
            echo "  - $(basename "$f")"
        done
    fi
    if [ ${#ELF_FILES[@]} -gt 0 ]; then
        echo -e "${CYAN}ELF files (.so/.elf/.axf/.out/.o):${NC}"
        for f in "${ELF_FILES[@]}"; do
            echo "  - $(basename "$f")"
        done
    fi
    
    # List only mode
    if [ "$LIST_ONLY" = true ]; then
        for archive in "${ARCHIVE_FILES[@]}"; do
            list_archive_contents "$archive"
        done
        for elf in "${ELF_FILES[@]}"; do
            list_elf_contents "$elf"
        done
        exit 0
    fi
    
    # Track used names to handle duplicates
    declare -A used_names
    local total_processed=0
    
    # ============================================================
    # Process Archive Files (.a, .lib)
    # ============================================================
    if [ ${#ARCHIVE_FILES[@]} -gt 0 ]; then
        echo ""
        draw_section "${BLUE}" "Processing Archives (${#ARCHIVE_FILES[@]} files)"
        echo ""
        
        for archive in "${ARCHIVE_FILES[@]}"; do
            local lib_name=$(basename "$archive")
            lib_name="${lib_name%.a}"
            lib_name="${lib_name%.lib}"
            lib_name=${lib_name#lib}  # Remove lib prefix
            
            # Handle duplicate names
            if [ -n "${used_names[$lib_name]}" ]; then
                local parent_dir=$(basename "$(dirname "$archive")")
                local unique_name="${lib_name}_${parent_dir}"
                local counter=1
                while [ -n "${used_names[$unique_name]}" ]; do
                    unique_name="${lib_name}_${parent_dir}_${counter}"
                    ((counter++))
                done
                log_warn "Duplicate name '$lib_name', using '$unique_name'"
                lib_name="$unique_name"
            fi
            used_names[$lib_name]=1
            
            decompile_library "$lib_name" "$archive" "$OUTPUT_DIR"
            ((total_processed++))
        done
    fi
    
    # ============================================================
    # Process ELF Files (.so, .elf, .axf, .out, .o)
    # ============================================================
    if [ ${#ELF_FILES[@]} -gt 0 ]; then
        echo ""
        draw_section "${CYAN}" "Processing ELF Files (${#ELF_FILES[@]} files)"
        echo ""
        
        local elf_count=0
        for elf_file in "${ELF_FILES[@]}"; do
            ((elf_count++))
            log_info "Processing ELF $elf_count/${#ELF_FILES[@]}: $(basename "$elf_file")"
            decompile_elf_file "$elf_file" "$OUTPUT_DIR" "$MODULE_STRATEGY"
            ((total_processed++))
        done
    fi
    
    # Generate global summary
    generate_global_summary "$OUTPUT_DIR"
    
    # Done
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
    log_info "Reverse engineering complete! ($total_processed files processed)"
    echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Output directory: $OUTPUT_DIR"
    echo ""
    echo "Next steps:"
    echo "  1. See $OUTPUT_DIR/SUMMARY.md for details"
    echo "  2. Decompiled sources are in each library's src/ directory"
    echo "  3. Headers are in each library's include/ directory (for archives)"
    echo ""
}

# Run
main "$@"
