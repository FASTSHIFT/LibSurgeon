# Similarity Analyzer

A high-performance tool for detecting similar source code files that can be unified using macros or templates.

## Features

- **Fast**: Uses [rapidfuzz](https://github.com/maxbachmann/rapidfuzz) (C++ implementation), ~100x faster than Python's difflib
- **Parallel**: Multi-process execution bypasses Python GIL for true parallelism
- **Smart Grouping**: Automatically groups files by naming patterns
- **Progress Display**: Real-time progress bar with ETA
- **Configurable**: Adjustable similarity threshold, file extensions, and worker count

## Installation

```bash
# Install dependencies
pip install rapidfuzz

# Or install all requirements
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
# Analyze a source directory
python similarity_analyzer.py ./src

# With implementation directory (to track which files are done)
python similarity_analyzer.py ./src --impl-dir ./impl

# Find all similar pairs globally
python similarity_analyzer.py ./src --find-pairs

# Custom similarity threshold (default: 80%)
python similarity_analyzer.py ./src -t 0.85 -p
```

### Command Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `src_dir` | | Source directory to analyze (required) |
| `--impl-dir` | `-i` | Implementation directory to check progress |
| `--threshold` | `-t` | Similarity threshold 0.0-1.0 (default: 0.80) |
| `--find-pairs` | `-p` | Find all similar file pairs globally |
| `--workers` | `-w` | Number of worker processes (0=auto) |
| `--ext` | | File extensions (default: .cpp .c .h .hpp) |
| `--quiet` | `-q` | Minimal output |
| `--version` | `-v` | Show version |

### Examples

```bash
# Analyze C files only
python similarity_analyzer.py ./src --ext .c .h

# Use 8 worker processes
python similarity_analyzer.py ./src -w 8 -p

# Find files with 90%+ similarity
python similarity_analyzer.py ./src -t 0.90 --find-pairs

# Quiet mode for scripting
python similarity_analyzer.py ./src -q
```

## Output

### Pattern-based Groups

Files are automatically grouped by naming patterns:

```
✅ Painter*Bitmap (15 files, 92% similar)
   Lines: 9611 | Impl: 0, Not: 15
     ○ PainterRGB565Bitmap.cpp (638 lines)
     ○ PainterRGB888Bitmap.cpp (550 lines)
     ...
```

- ✅ = 90%+ similarity (excellent template candidate)
- 🔶 = 70-90% similarity (good candidate)
- ❌ = <70% similarity (probably too different)

### Template Candidates

Shows groups that exceed the similarity threshold:

```
📦 LCD8*DebugPrinter (99%, saves ~435 lines)
     ○ LCD8ABGR2222DebugPrinter.cpp
     ○ LCD8ARGB2222DebugPrinter.cpp
```

### Global Similar Pairs

When using `--find-pairs`, shows similar files not caught by pattern grouping:

```
Found 11 additional similar pairs:
  89%: ✓Box.cpp <-> ✓PixelDataWidget.cpp
  85%: ✓Image.cpp <-> ✓Button.cpp
```

## Algorithm

1. **Load Phase**: Files are loaded in parallel using multiprocessing
2. **Normalization**: Code is normalized by:
   - Removing block comments
   - Replacing class names with placeholders
   - Replacing variant keywords (RGB565, ARGB8888, etc.)
   - Compressing whitespace
3. **Grouping**: Files are grouped by filename patterns
4. **Comparison**: 
   - Group analysis: All pairs within each group
   - Global search: All pairs across files (with line-count filtering)
5. **Output**: Results sorted by similarity

## Performance

| Backend | Speed | Notes |
|---------|-------|-------|
| rapidfuzz | ~600/s | C++ implementation |
| difflib | ~5/s | Python fallback |

For a typical project with 143 files (4200 pairs):
- rapidfuzz: ~14 seconds
- difflib: ~4+ hours

## API Usage

```python
from similarity_analyzer import (
    normalize_code,
    calc_similarity,
    find_similar_pairs,
    FileData
)

# Compare two strings
sim = calc_similarity("code1", "code2")
print(f"Similarity: {sim:.0%}")

# Analyze files
file_data = {
    'file1.cpp': FileData('file1.cpp', 100, normalized1),
    'file2.cpp': FileData('file2.cpp', 120, normalized2),
}
pairs = find_similar_pairs(file_data, threshold=0.8, num_workers=4)
```

## License

MIT License - See [LICENSE](../LICENSE)
