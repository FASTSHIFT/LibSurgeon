# LibSurgeon 🔬

[![CI](https://github.com/YOUR_USERNAME/LibSurgeon/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/LibSurgeon/actions/workflows/ci.yml)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**Static Library & ELF Dissector - Automated Reverse Engineering with Ghidra**

LibSurgeon is a powerful automated tool that performs surgical extraction of C/C++ source code from static library archives and ELF binaries. It leverages Ghidra's advanced decompilation engine to reconstruct readable source code from compiled binaries.

## ✨ Features

- 🔍 **Unified Processing**: One command processes ALL supported file types
- 🔄 **Recursive Scanning**: Automatically finds all supported files in subdirectories
- ⚡ **Parallel Processing**: Multi-threaded decompilation with configurable job count
- 📊 **Quality Evaluation**: Automated decompilation quality assessment
- 📁 **Organized Output**: Clean directory structure with sources, headers, and logs
- 🧩 **Module Grouping**: Smart function grouping strategies for ELF files
- 🎯 **Flexible Filtering**: Include/exclude patterns for targeted processing
- 📝 **Documentation**: Auto-generated README and summary reports
- 🐍 **Pure Python**: Main tools rewritten in Python for better portability

## 📦 Supported File Types

| Type | Extensions | Processing Method |
|------|------------|-------------------|
| **Archives** | `.a`, `.lib` | Extract `.o` files, then decompile each |
| **ELF Files** | `.so`, `.elf`, `.axf`, `.out`, `.o` | Direct decompilation |

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/LibSurgeon.git
cd LibSurgeon

# Install Python dependencies (optional, for development)
pip install -r requirements-dev.txt

# Ensure Ghidra is installed
# Download from: https://ghidra-sre.org/
```

### Requirements

- **Python** 3.8 or later
- **Ghidra** 11.0 or later (with analyzeHeadless support)
- **Java** 17 or later (required by Ghidra)
- **GNU Binutils** (`ar` command for archive extraction)

### Basic Usage

```bash
# Process a static library
python libsurgeon.py -g /path/to/ghidra lib.a

# Process all archives in a directory
python libsurgeon.py -g /path/to/ghidra ./my_sdk/

# With quality evaluation
python libsurgeon.py -g /path/to/ghidra --evaluate library.a

# Parallel processing (4 jobs)
python libsurgeon.py -g /path/to/ghidra -j 4 ./libraries/
```

## 🛠️ Tools

LibSurgeon includes several Python tools:

### `libsurgeon.py` - Main CLI Tool

The primary command-line interface for batch decompilation.

```bash
python libsurgeon.py -g /path/to/ghidra [options] <target>

Options:
  -g, --ghidra PATH     Path to Ghidra installation (REQUIRED)
  -o, --output DIR      Output directory (default: ./libsurgeon_output)
  -j, --jobs NUM        Number of parallel jobs (default: 1)
  -i, --include PATTERN Only include matching files (repeatable)
  -e, --exclude PATTERN Exclude matching files (repeatable)
  --evaluate            Run quality evaluation after decompilation
  --list                List file contents without decompiling
  -c, --clean           Clean previous output before processing
```

### `batch_decompile.py` - Batch Decompilation

Standalone batch decompiler for object files.

```bash
python batch_decompile.py -g /path/to/ghidra -i input.a -o output/
python batch_decompile.py -g /path/to/ghidra -i extracted_dir/ -o output/ -j 4
```

### `evaluate_quality.py` - Quality Assessment

Analyze decompilation quality with detailed metrics.

```bash
python evaluate_quality.py ./decompiled_src/
python evaluate_quality.py ./output/ --verbose
python evaluate_quality.py ./output/ --json report.json
```

**Quality Metrics:**
- `halt_baddata`: Ghidra analysis failures (critical)
- `undefined types`: Generic type placeholders
- `excessive casts`: Complex pointer manipulations
- `demangled names`: Successfully recovered C++ symbols

**Quality Grades:**
| Grade | Score | Description |
|-------|-------|-------------|
| A | 90+ | Excellent - highly readable |
| B | 80+ | Good - minor issues |
| C | 70+ | Fair - needs cleanup |
| D | 50+ | Poor - significant issues |
| F | <50 | Failed - mostly unusable |

### `format.sh` - Code Formatting

Automatic code formatting and linting (shell script).

```bash
./format.sh                    # Format all files
./format.sh --check            # Check without formatting (CI mode)
```

## 📊 Output Structure

```
libsurgeon_output/
├── library_name/
│   ├── src/           # Decompiled C/C++ source files
│   │   ├── Module1.cpp
│   │   ├── Module2.cpp
│   │   └── ...
│   ├── include/       # Header files (if found)
│   ├── logs/          # Processing logs
│   │   ├── ghidra_main.log
│   │   └── failed_files.txt
│   ├── quality_report.json  # Quality metrics (if --evaluate)
│   └── README.md      # Library-specific documentation
└── SUMMARY.md         # Overall processing summary
```

## 🧪 Testing

LibSurgeon includes a comprehensive test suite with code coverage support.

```bash
# Install test dependencies
pip install pytest pytest-cov

# Build test fixtures
cd tests && bash build_fixtures.sh && cd ..

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=. --cov-report=html

# View coverage report
open htmlcov/index.html
```

## 🔧 Development

### Code Style

This project uses [black](https://github.com/psf/black) for code formatting and [isort](https://pycqa.github.io/isort/) for import sorting.

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Format code
./format.sh

# Check formatting (CI mode)
./format.sh --check
```

### CI/CD

GitHub Actions runs on every push and pull request:

1. **Lint & Format Check**: black, isort, flake8
2. **Unit Tests**: Python 3.8-3.12
3. **Code Coverage**: Uploaded to Codecov
4. **Integration Tests**: Full Ghidra pipeline (main branch only)

## 📋 Examples

### Decompile xxGFX Library

```bash
# Extract and decompile ARM library
python libsurgeon.py -g ~/ghidra_11.2.1_PUBLIC \
    -o xxgfx_output \
    --evaluate \
    ./lib.a

# Check quality
python evaluate_quality.py xxgfx_output/lib/src/
```

### Process Multiple Libraries

```bash
# Process all .a files in SDK
python libsurgeon.py -g /opt/ghidra \
    -j 4 \
    --evaluate \
    ./vendor/sdk/lib/
```

### Filter Specific Libraries

```bash
# Only process libgre* libraries
python libsurgeon.py -g /opt/ghidra \
    -i "libgre*" \
    ./vendor/

# Exclude test libraries
python libsurgeon.py -g /opt/ghidra \
    -e "*test*" \
    ./libraries/
```

## 🔍 Troubleshooting

### Common Issues

**"Ghidra analyzeHeadless not found"**
- Ensure the path points to the Ghidra installation root directory
- Verify `support/analyzeHeadless` exists in the Ghidra folder

**"Java not found" or version issues**
- Install Java 17+ (required by Ghidra 11+)
- Set `JAVA_HOME` environment variable

**"ar command not found"**
- Install GNU binutils: `apt install binutils` (Debian/Ubuntu)

**High `halt_baddata` count**
- This usually indicates Ghidra couldn't analyze the binary properly
- Try using x86-64 libraries instead of ARM for better decompilation
- ARM Thumb code is particularly challenging for decompilers

### Debug Mode

For troubleshooting, check the logs directory:

```bash
# View Ghidra logs
cat libsurgeon_output/library_name/logs/ghidra_main.log

# Check failed files
cat libsurgeon_output/library_name/logs/failed_files.txt
```

## 📜 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- [Ghidra](https://ghidra-sre.org/) - NSA's Software Reverse Engineering Framework
- [black](https://github.com/psf/black) - The uncompromising Python code formatter

## ⚠️ Disclaimer

This tool is intended for:
- Educational purposes
- Security research
- Compatibility analysis
- Legacy code recovery

Please respect software licenses and intellectual property rights. Only use this tool on binaries you have the legal right to analyze.
