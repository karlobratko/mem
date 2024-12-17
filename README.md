# Memory Allocator Library

A single-header [STB-style](https://github.com/nothings/stb) memory allocation library inspired
by [Zig](https://ziglang.org/) allocators design.
**Currently, a work in progress.**

## Rationale

Memory management is one of the most critical aspects of C programming, directly impacting program correctness,
performance, and maintainability. While C gives developers complete control over memory, this control often leads to
diverse and inconsistent allocation patterns across codebases.

This library addresses several key challenges:

1. **Unified Interface**: By providing a consistent interface for all allocation strategies, the library makes code more
   readable and maintainable. Developers can focus on _what_ they're allocating rather than _how_.

2. **Pluggable Allocators**: Different applications have different memory requirements. Some need speed, others need to
   work with fixed memory, and others need detailed tracking. This library allows switching allocation strategies
   without changing the application code.

3. **Type Safety**: The convenience macros provide type-safe allocation, reducing common errors while maintaining C's
   direct memory control.

4. **Debugging Support**: Built-in support for logging and debugging makes tracking memory issues easier without
   modifying application code.

5. **Minimal Overhead**: The library is designed to add minimal overhead when using basic allocators, while providing powerful
   features when needed.

By standardizing memory allocation patterns, this library helps developers focus on their application logic while
maintaining full control over memory management strategies. The ability to easily swap allocators makes it possible to
optimize memory usage for different scenarios without widespread code changes.

## Features

- Single header (`mem.h`)
- Aligned memory allocation
- Custom allocator support through vtable interface
- Zero dependencies beyond C standard library
- C11 or later required for `alignas` support

## Currently Supported Allocators

- LIBC allocator (malloc/free wrapper)
- Logging allocator
- Fixed buffer allocator

## Planned Allocators

- Arena allocator
- Stack allocator
- Pool allocator
- More to come as existing ones are tested and stable

## Interface

```c
// Core allocation functions
void *alloc_raw(const allocator_t *allocator, size_t size, size_t align);
bool  resize_raw(const allocator_t *allocator, void *buf, size_t size, size_t align, size_t new_size);
void  dealloc_raw(const allocator_t *allocator, void *buf, size_t size, size_t align);

// Convenience macros for type-safe allocation
#define alloc(allocator, type, len) 
#define resize(allocator, type, buf, len, new_len)
#define dealloc(allocator, type, buf, len)
#define create(allocator, type)
#define destroy(allocator, type, buf)
```

## Allocator Interfaces

```c
// ----- LIBC allocator -----
const allocator_t libc_allocator;

// ----- LOGGING allocator -----
typedef struct logging_allocator_t logging_allocator_t;

logging_allocator_t logging_allocator_init(const allocator_t *wrapped, FILE *success_file, FILE *failure_file);
logging_allocator_t logging_allocator_init_default(const allocator_t *wrapped);
allocator_t         logging_allocator_to_allocator(logging_allocator_t *ctx);

// ----- FIXED BUFFER allocator -----
typedef struct fixed_buffer_allocator_t fixed_buffer_allocator_t;

fixed_buffer_allocator_t fixed_buffer_allocator_init(void *buf, size_t size);
allocator_t              fixed_buffer_allocator_to_allocator(fixed_buffer_allocator_t *ctx);
void                     fixed_buffer_allocator_reset(fixed_buffer_allocator_t *ctx);
```

## Usage Example

```c
#define MEM_IMPLEMENTATION
#include "mem.h"

typedef struct MyStruct {
    int x;
    float y;
    char data[64];
} MyStruct;

int main(void) {
    // Initialize logging allocator wrapping libc allocator
    logging_allocator_t logging = logging_allocator_init(&libc_allocator, stdout, stderr);
    allocator_t allocator = logging_allocator_to_allocator(&logging);

    // Basic allocation
    int* numbers = alloc(&allocator, int, 10);  // This will log the allocation
    if (numbers) {
        // Use the memory
        for (int i = 0; i < 10; i++) {
            numbers[i] = i;
        }

        // Free when done - this will also be logged
        dealloc(&allocator, int, numbers, 10);
    }

    // Single object allocation
    MyStruct* obj = create(&allocator, MyStruct);  // Logs allocation
    if (obj) {
        // Use the object
        obj->x = 42;
        obj->y = 3.14f;
        destroy(&allocator, MyStruct, obj);  // Logs deallocation
    }
}
```

## Implementing Custom Allocators

Custom allocators can be implemented by providing a vtable with allocation functions:

```c
typedef struct {
    void *(*_alloc  )(void *ctx, size_t size, size_t align);
    bool  (*_resize )(void *ctx, void *buf, size_t size, size_t align, size_t new_size);
    void  (*_dealloc)(void *ctx, void *buf, size_t size, size_t align);
} allocator_vtable_t;

typedef struct {
    void *ctx;
    const allocator_vtable_t *vtable;
} allocator_t;
```