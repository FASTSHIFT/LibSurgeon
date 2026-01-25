/**
 * LibSurgeon Test Fixture - Simple C Library
 * 
 * This is a minimal C library used for testing LibSurgeon's
 * decompilation functionality without requiring Ghidra.
 * 
 * Compile with:
 *   gcc -c test_library.c -o test_library.o
 *   ar rcs libtest.a test_library.o
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// ============================================================
// Simple Functions
// ============================================================

/**
 * Add two integers
 */
int add(int a, int b) {
    return a + b;
}

/**
 * Multiply two integers
 */
int multiply(int a, int b) {
    return a * b;
}

/**
 * Calculate factorial (recursive)
 */
int factorial(int n) {
    if (n <= 1) {
        return 1;
    }
    return n * factorial(n - 1);
}

// ============================================================
// Data Structures
// ============================================================

typedef struct {
    int x;
    int y;
} Point;

typedef struct {
    Point origin;
    int width;
    int height;
} Rectangle;

/**
 * Initialize a point
 */
void point_init(Point* p, int x, int y) {
    if (p != NULL) {
        p->x = x;
        p->y = y;
    }
}

/**
 * Initialize a rectangle
 */
void rect_init(Rectangle* r, int x, int y, int w, int h) {
    if (r != NULL) {
        point_init(&r->origin, x, y);
        r->width = w;
        r->height = h;
    }
}

/**
 * Calculate rectangle area
 */
int rect_area(const Rectangle* r) {
    if (r == NULL) {
        return 0;
    }
    return r->width * r->height;
}

/**
 * Check if point is inside rectangle
 */
bool rect_contains_point(const Rectangle* r, const Point* p) {
    if (r == NULL || p == NULL) {
        return false;
    }
    return (p->x >= r->origin.x && 
            p->x < r->origin.x + r->width &&
            p->y >= r->origin.y && 
            p->y < r->origin.y + r->height);
}

// ============================================================
// String Operations
// ============================================================

/**
 * Calculate string length
 */
int string_length(const char* str) {
    if (str == NULL) {
        return 0;
    }
    
    int len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len;
}

/**
 * Copy string
 */
void string_copy(char* dest, const char* src, int max_len) {
    if (dest == NULL || src == NULL || max_len <= 0) {
        return;
    }
    
    int i;
    for (i = 0; i < max_len - 1 && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    dest[i] = '\0';
}

// ============================================================
// Bitwise Operations
// ============================================================

/**
 * Count set bits in integer
 */
int count_bits(uint32_t value) {
    int count = 0;
    while (value) {
        count += value & 1;
        value >>= 1;
    }
    return count;
}

/**
 * Reverse bits in byte
 */
uint8_t reverse_bits(uint8_t b) {
    b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
    b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
    b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
    return b;
}

// ============================================================
// Global State (for testing static analysis)
// ============================================================

static int global_counter = 0;

void increment_counter(void) {
    global_counter++;
}

int get_counter(void) {
    return global_counter;
}

void reset_counter(void) {
    global_counter = 0;
}
