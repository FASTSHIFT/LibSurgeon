#!/bin/bash
# Build test fixtures for LibSurgeon

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"

echo "Building test fixtures..."

# Check for gcc
if ! command -v gcc &> /dev/null; then
    echo "Error: gcc not found"
    exit 1
fi

# Check for ar
if ! command -v ar &> /dev/null; then
    echo "Error: ar not found"
    exit 1
fi

cd "$FIXTURES_DIR"

# Compile test library (x86-64)
echo "  Compiling test_library.c..."
gcc -c -g -O0 test_library.c -o test_library.o

# Create static archive
echo "  Creating libtest.a..."
ar rcs libtest.a test_library.o

# Show results
echo ""
echo "Built fixtures:"
ls -la *.o *.a 2>/dev/null || true

echo ""
echo "Archive contents:"
ar -t libtest.a

echo ""
echo "Done!"
