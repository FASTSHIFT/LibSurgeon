#!/bin/bash
# Build test fixtures for LibSurgeon
# Creates all supported file types for comprehensive testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"

echo "Building test fixtures..."
echo "========================="

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

# Clean previous builds
echo "Cleaning previous builds..."
rm -f *.o *.a *.so *.elf *.axf *.out *.lib 2>/dev/null || true

# ============================================================
# Compile object file (.o)
# ============================================================
echo ""
echo "1. Building object file (.o)..."
gcc -c -g -O0 test_library.c -o test_library.o
echo "   Created: test_library.o"

# ============================================================
# Create static archive (.a)
# ============================================================
echo ""
echo "2. Building static archive (.a)..."
ar rcs libtest.a test_library.o
echo "   Created: libtest.a"

# ============================================================
# Create Windows-style static library (.lib)
# Note: This is just a copy of .a with different extension
# ============================================================
echo ""
echo "3. Building Windows-style library (.lib)..."
cp libtest.a libtest.lib
echo "   Created: libtest.lib"

# ============================================================
# Create shared library (.so)
# ============================================================
echo ""
echo "4. Building shared library (.so)..."
gcc -shared -fPIC -g -O0 test_library.c -o libtest.so
# Also create versioned .so
cp libtest.so libtest.so.1.0.0
echo "   Created: libtest.so, libtest.so.1.0.0"

# ============================================================
# Create ELF executable (.elf)
# ============================================================
echo ""
echo "5. Building ELF executable (.elf)..."
# Create a simple main wrapper
cat > test_main.c << 'EOF'
extern int add(int a, int b);
extern int multiply(int a, int b);

int main(void) {
    int result = add(1, 2);
    result = multiply(result, 3);
    return result;
}
EOF
gcc -g -O0 test_main.c test_library.c -o test_program.elf
rm -f test_main.c
echo "   Created: test_program.elf"

# ============================================================
# Create ARM-style executable (.axf)
# Note: Just a copy with different extension for testing
# ============================================================
echo ""
echo "6. Building ARM-style executable (.axf)..."
cp test_program.elf test_program.axf
echo "   Created: test_program.axf"

# ============================================================
# Create generic output executable (.out)
# ============================================================
echo ""
echo "7. Building generic executable (.out)..."
cp test_program.elf test_program.out
echo "   Created: test_program.out"

# ============================================================
# Summary
# ============================================================
echo ""
echo "========================="
echo "Built fixtures summary:"
echo "========================="
echo ""
echo "Archive files:"
ls -la *.a *.lib 2>/dev/null || echo "  (none)"
echo ""
echo "ELF files:"
ls -la *.o *.so* *.elf *.axf *.out 2>/dev/null || echo "  (none)"
echo ""
echo "Archive contents (libtest.a):"
ar -t libtest.a
echo ""
echo "File type verification:"
file *.a *.lib *.o *.so *.elf *.axf *.out 2>/dev/null || true
echo ""
echo "Done!"