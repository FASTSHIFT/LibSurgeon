#!/bin/bash
# -*- coding: utf-8 -*-
#
# LibSurgeon - Static Library Reverse Engineering Tool
# Automated decompilation of .a archive files to C/C++ source code
#
# Usage:
#   ./libsurgeon.sh [options] <target_directory>
#
# Options:
#   -g, --ghidra <path>     Path to Ghidra installation (required)
#   -o, --output <dir>      Output directory (default: ./libsurgeon_output)
#   -j, --jobs <num>        Number of parallel jobs (default: auto)
#   -c, --clean             Clean previous output
#   -l, --list              List archive contents only
#   -h, --help              Show help message
#

set -e

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
    local eta=$5
    
    local percentage=$((current * 100 / total))
    local bar=$(draw_progress_bar $current $total)
    
    # Clear current line and show progress
    echo -ne "\r\033[K"
    
    # Progress bar line
    echo -ne "${CYAN}[${bar}]${NC} ${BOLD}${percentage}%${NC} (${current}/${total})"
    
    # Time info
    if [ "$eta" -gt 0 ]; then
        echo -ne " | Elapsed: $(format_time $elapsed) | ETA: ${YELLOW}$(format_time $eta)${NC}"
    else
        echo -ne " | Elapsed: $(format_time $elapsed)"
    fi
    
    echo ""
    
    # Current file
    echo -e "${DIM}  -> Processing: ${NC}${GREEN}${filename}${NC}"
    
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
Usage: $0 [options] <target_directory>

LibSurgeon scans the target directory for static library (.a) files and
header files, then decompiles all object files using Ghidra.

Options:
  -g, --ghidra <path>     Path to Ghidra installation (REQUIRED)
  -o, --output <dir>      Output directory (default: ./libsurgeon_output)
  -j, --jobs <num>        Number of parallel jobs (default: $PARALLEL_JOBS)
  -i, --include <pattern> Only include archives matching pattern (can be used multiple times)
  -e, --exclude <pattern> Exclude archives matching pattern (can be used multiple times)
  -c, --clean             Clean previous output before processing
  -l, --list              List archive contents without decompiling
  -h, --help              Show this help message

Filter Rules:
  - If --include is specified, only matching archives are processed
  - If --exclude is specified, matching archives are skipped
  - --include is applied first, then --exclude
  - Patterns support wildcards: * (any chars), ? (single char), [abc] (char set)

Examples:
  $0 -g /opt/ghidra ./my_sdk/lib
  $0 -g /opt/ghidra -j 8 -o ./output ./vendor/libs
  $0 -g /opt/ghidra -i "*touchgfx*" ./sdk           # Only process touchgfx
  $0 -g /opt/ghidra -i "libfoo*" -i "libbar*" ./libs # Process foo and bar only
  $0 -g /opt/ghidra -e "*jpeg*" -e "*png*" ./third_party
  $0 -g /opt/ghidra --include "*core*" --exclude "*test*" ./libs
  $0 --list ./my_sdk/lib

Output Structure:
  libsurgeon_output/
  ├── <library_name>/
  │   ├── src/           # Decompiled C/C++ source files
  │   ├── include/       # Copied header files (if found)
  │   └── logs/          # Ghidra processing logs
  └── SUMMARY.md         # Overview report

Notes:
  - Ghidra 11+ with Java 17+ is required
  - ARM Cortex-M processor is assumed (can be modified in script)
  - Original symbols are preserved if not stripped
  - Each .o file produces one .cpp file

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
    
    log_info "Dependencies check passed"
}

# Scan directory for .a files
scan_archives() {
    local dir="$1"
    find "$dir" -name "*.a" -type f 2>/dev/null | sort
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
    
    if [ $excluded_count -gt 0 ]; then
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
    if [ $status -eq 0 ] && [ -f "$final_file" ]; then
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
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  Processing: ${BOLD}${lib_name}${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    
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
    echo -e "${YELLOW}+----------------------------------------------------------------+${NC}"
    echo -e "${YELLOW}|          Decompilation Progress - ${lib_name} (${PARALLEL_JOBS} threads)${NC}"
    echo -e "${YELLOW}+----------------------------------------------------------------+${NC}"
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
            while [ $running -ge $PARALLEL_JOBS ]; do
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
                
                if [ "$completed" -gt "$prev_count" ]; then
                    last_completed_file=$(tail -1 "$progress_file" 2>/dev/null | cut -d: -f2)
                    prev_count=$completed
                fi
                
                local now=$(date +%s)
                local elapsed=$((now - start_time))
                local eta=0
                if [ $completed -gt 0 ]; then
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
        while [ $running -gt 0 ]; do
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
            
            if [ "$completed" -gt "$prev_count" ]; then
                last_completed_file=$(tail -1 "$progress_file" 2>/dev/null | cut -d: -f2)
                prev_count=$completed
            fi
            
            local now=$(date +%s)
            local elapsed=$((now - start_time))
            local eta=0
            if [ $completed -gt 0 ]; then
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
    
    # Statistics
    local success_count=$(grep -c "^OK:" "$progress_file" 2>/dev/null || echo 0)
    local fail_count=$(grep -c "^FAIL:" "$progress_file" 2>/dev/null || echo 0)
    
    # Record failed files
    grep "^FAIL:" "$progress_file" 2>/dev/null | cut -d: -f2 > "$lib_output/logs/failed_files.txt"
    
    # Cleanup
    rm -f "$progress_file"
    rm -rf "$extract_dir"
    
    # Display statistics
    echo ""
    echo -e "${YELLOW}+----------------------------------------------------------------+${NC}"
    echo -e "${YELLOW}|                    Statistics - ${lib_name}${NC}"
    echo -e "${YELLOW}+----------------------------------------------------------------+${NC}"
    echo -e "  ${GREEN}Success:${NC} $success_count files"
    if [ $fail_count -gt 0 ]; then
        echo -e "  ${RED}Failed:${NC} $fail_count files (see logs/failed_files.txt)"
    fi
    echo -e "  ${BLUE}Duration:${NC} $(format_time $total_elapsed)"
    if [ $total -gt 0 ] && [ $total_elapsed -gt 0 ]; then
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
    
    # Validate target directory
    if [ -z "$TARGET_DIR" ]; then
        log_error "Target directory not specified."
        show_help
        exit 1
    fi
    
    if [ ! -d "$TARGET_DIR" ]; then
        log_error "Target directory does not exist: $TARGET_DIR"
        exit 1
    fi
    
    TARGET_DIR=$(realpath "$TARGET_DIR")
    
    # Scan for archives
    log_info "Scanning directory: $TARGET_DIR"
    
    mapfile -t ARCHIVES < <(scan_archives "$TARGET_DIR")
    
    if [ ${#ARCHIVES[@]} -eq 0 ]; then
        log_error "No .a archive files found in $TARGET_DIR"
        exit 1
    fi
    
    log_info "Found ${#ARCHIVES[@]} archive(s)"
    
    # Apply include/exclude filters
    if [ ${#INCLUDE_PATTERNS[@]} -gt 0 ] || [ ${#EXCLUDE_PATTERNS[@]} -gt 0 ]; then
        if [ ${#INCLUDE_PATTERNS[@]} -gt 0 ]; then
            log_info "Include filters: ${INCLUDE_PATTERNS[*]}"
        fi
        if [ ${#EXCLUDE_PATTERNS[@]} -gt 0 ]; then
            log_info "Exclude filters: ${EXCLUDE_PATTERNS[*]}"
        fi
        filter_archives ARCHIVES
    fi
    
    if [ ${#ARCHIVES[@]} -eq 0 ]; then
        log_error "No archives left after filtering"
        exit 1
    fi
    
    log_info "Archives to process:"
    for archive in "${ARCHIVES[@]}"; do
        echo "  - $(basename "$archive")"
    done
    
    # List only mode
    if [ "$LIST_ONLY" = true ]; then
        for archive in "${ARCHIVES[@]}"; do
            list_archive_contents "$archive"
        done
        exit 0
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
    
    # Track used library names to handle duplicates
    declare -A used_lib_names
    
    # Process each archive
    for archive in "${ARCHIVES[@]}"; do
        local lib_name=$(basename "$archive" .a)
        lib_name=${lib_name#lib}  # Remove lib prefix
        
        # Handle duplicate library names
        if [ -n "${used_lib_names[$lib_name]}" ]; then
            # Generate unique name using parent directory
            local parent_dir=$(basename "$(dirname "$archive")")
            local unique_name="${lib_name}_${parent_dir}"
            
            # If still duplicate, add counter
            local counter=1
            while [ -n "${used_lib_names[$unique_name]}" ]; do
                unique_name="${lib_name}_${parent_dir}_${counter}"
                ((counter++))
            done
            
            log_warn "Duplicate library name '$lib_name', using '$unique_name'"
            lib_name="$unique_name"
        fi
        
        used_lib_names[$lib_name]=1
        
        decompile_library "$lib_name" "$archive" "$OUTPUT_DIR"
    done
    
    # Generate global summary
    generate_global_summary "$OUTPUT_DIR"
    
    # Done
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
    log_info "Reverse engineering complete!"
    echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Output directory: $OUTPUT_DIR"
    echo ""
    echo "Next steps:"
    echo "  1. See $OUTPUT_DIR/SUMMARY.md for details"
    echo "  2. Decompiled sources are in each library's src/ directory"
    echo "  3. Headers are in each library's include/ directory"
    echo ""
}

# Run
main "$@"
