#!/bin/bash
# LibSurgeon Code Formatter
# Formats all Python files using black, isort, and flake8

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
CHECK_ONLY=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --check|-c)
            CHECK_ONLY=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--check]"
            echo "  --check, -c    Check only, don't modify files"
            echo "  --help, -h     Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Find Python files
FILES=$(find . -name "*.py" \
    ! -path "./.venv/*" \
    ! -path "./venv/*" \
    ! -path "./__pycache__/*" \
    ! -path "./.git/*" \
    ! -path "./build/*" \
    ! -path "./dist/*" \
    ! -path "./*.egg-info/*" \
    | sort)

FILE_COUNT=$(echo "$FILES" | wc -l)
echo -e "${BLUE}Found $FILE_COUNT Python file(s)${NC}"
echo ""

ALL_PASSED=true

# isort
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  Import Sorting (isort)${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
if command -v isort &> /dev/null || python -m isort --version &> /dev/null; then
    if $CHECK_ONLY; then
        if python -m isort --check-only --profile black $FILES; then
            echo -e "${GREEN}✓ isort: passed${NC}"
        else
            echo -e "${RED}✗ isort: issues found${NC}"
            ALL_PASSED=false
        fi
    else
        python -m isort --profile black $FILES
        echo -e "${GREEN}✓ isort: completed${NC}"
    fi
else
    echo -e "${YELLOW}  Warning: isort not installed. Run: pip install isort${NC}"
fi
echo ""

# black
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  Code Formatting (black)${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
if command -v black &> /dev/null || python -m black --version &> /dev/null; then
    if $CHECK_ONLY; then
        if python -m black --check $FILES; then
            echo -e "${GREEN}✓ black: passed${NC}"
        else
            echo -e "${RED}✗ black: issues found${NC}"
            ALL_PASSED=false
        fi
    else
        python -m black $FILES
        echo -e "${GREEN}✓ black: completed${NC}"
    fi
else
    echo -e "${YELLOW}  Warning: black not installed. Run: pip install black${NC}"
fi
echo ""

# flake8 (check only)
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  Linting (flake8)${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
if command -v flake8 &> /dev/null || python -m flake8 --version &> /dev/null; then
    if python -m flake8 --max-line-length 88 --extend-ignore E203,E501,W503 $FILES; then
        echo -e "${GREEN}✓ flake8: no issues${NC}"
    else
        echo -e "${RED}✗ flake8: issues found${NC}"
        ALL_PASSED=false
    fi
else
    echo -e "${YELLOW}  Warning: flake8 not installed. Run: pip install flake8${NC}"
fi
echo ""

# Summary
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  Summary${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
if $ALL_PASSED; then
    if $CHECK_ONLY; then
        echo -e "${GREEN}✓ All checks passed!${NC}"
    else
        echo -e "${GREEN}✓ Formatting complete!${NC}"
    fi
    exit 0
else
    echo -e "${RED}✗ Some checks failed${NC}"
    exit 1
fi
