#ifndef MEM_H
#define MEM_H

#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MEMAPI
#ifdef MEM_STATIC
#define MEMAPI static
#else
#define MEMAPI extern
#endif
#endif

typedef struct {
    void *(*_alloc)(void *ctx, size_t size, size_t align);

    bool (*_resize)(void *ctx, void *buf, size_t size, size_t align, size_t new_size);

    void (*_dealloc)(void *ctx, void *buf, size_t size, size_t align);
} allocator_vtable_t;

typedef struct {
    void *ctx;
    const allocator_vtable_t *vtable;
} allocator_t;

MEMAPI void *alloc_raw(const allocator_t *allocator, size_t size, size_t align);

MEMAPI bool resize_raw(const allocator_t *allocator, void *buf, size_t size, size_t align, size_t new_size);

MEMAPI void dealloc_raw(const allocator_t *allocator, void *buf, size_t size, size_t align);

// TODO: Add realloc functionality, which combines resize, alloc and free.

#define alloc(allocator, type, len) (alloc_raw((allocator), (sizeof(type) * len), alignof(type)))

#define resize(allocator, type, buf, len, new_len) (resize_raw((allocator), (buf), (sizeof(type) * len), alignof(type), (sizeof(type) * new_len)))

#define dealloc(allocator, type, buf, len) (dealloc_raw((allocator), (buf), (sizeof(type) * len), alignof(type)))

#define create(allocator, type) alloc(allocator, type, 1)

#define destroy(allocator, type, buf) dealloc(allocator, type, buf, 1)

// ----- LIBC allocator -----

MEMAPI const allocator_t libc_allocator;

// ----- LOGGING allocator -----

typedef struct {
    const allocator_t *wrapped;
    FILE *success_file;
    FILE *failure_file;
} logging_allocator_t;

MEMAPI logging_allocator_t logging_allocator_init(const allocator_t *wrapped, FILE *success_file, FILE *failure_file);

MEMAPI logging_allocator_t logging_allocator_init_default(const allocator_t *wrapped);

MEMAPI allocator_t logging_allocator_to_allocator(logging_allocator_t *ctx);

// ----- ARENA allocator -----

typedef struct {
    void *buf;
    const size_t size;
    size_t end;
} arena_allocator_t;

MEMAPI arena_allocator_t arena_allocator_init(void *buf, size_t size);

MEMAPI allocator_t arena_allocator_to_allocator(arena_allocator_t *ctx);

MEMAPI void arena_allocator_reset(arena_allocator_t *ctx);

#ifdef __cplusplus
}
#endif

#endif

//#define MEM_IMPLEMENTATION
#ifdef MEM_IMPLEMENTATION

#ifndef MEMIMPL
#ifdef MEM_STATIC
#define MEMIMPL static inline
#else
#define MEMIMPL extern inline
#endif
#endif

#ifndef MEMUTIL
#define MEMUTIL static
#endif

#ifndef MEM_ASSERT
#include <assert.h>
#define MEM_ASSERT(x) assert(x)
#endif

#if !defined(NDEBUG) && !defined(MEM_DEBUG)
#define MEM_DEBUG
#endif

#define MEM_NOTUSED(x) (void)(x)

#include <stdint.h>
typedef uint32_t mem__u32;
typedef uintptr_t mem__uptr;

#ifndef MEM_BYTE_ORDER
#define MEM_BYTE_ORDER
#define MEM_BIG_ENDIAN    0
#define MEM_LITTLE_ENDIAN 0

#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#undef MEM_LITTLE_ENDIAN
#define MEM_LITTLE_ENDIAN 1
#elif defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#undef MEM_BIG_ENDIAN
#define MEM_BIG_ENDIAN 1
#elif defined(_WIN32) || defined(_WIN64)
#undef MEM_LITTLE_ENDIAN
#define MEM_LITTLE_ENDIAN 1
#else
#if ((*(uint8_t *)&(uint32_t){1}) == 1)
#undef MEM_LITTLE_ENDIAN
#define MEM_LITTLE_ENDIAN 1
#else
#undef MEM_BIG_ENDIAN
#define MEM_BIG_ENDIAN 1
#endif
#endif
#endif

#include <string.h>
#include <stdlib.h>

MEMUTIL bool mem__align_is_valid(const size_t align) {
    return align > 0 && (align & (align - 1)) == 0;
}

MEMUTIL mem__uptr mem__align_backward(const mem__uptr address, const size_t alignment) {
    MEM_ASSERT(mem__align_is_valid(alignment));

    return address & ~(alignment - 1);
}

MEMUTIL bool mem__is_aligned(const mem__uptr address, const size_t alignment) {
    MEM_ASSERT(mem__align_is_valid(alignment));

    return mem__align_backward(address, alignment) == address;
}

MEMUTIL mem__uptr mem__align_forward(const mem__uptr address, const size_t alignment) {
    MEM_ASSERT(mem__align_is_valid(alignment));

    return mem__align_backward(address + (alignment - 1), alignment);
}

MEMUTIL size_t mem__align_pointer_offset(const void *ptr, const size_t alignment) {
    MEM_ASSERT(mem__align_is_valid(alignment));

    return (mem__uptr) ptr & (alignment - 1);
}

MEMUTIL bool mem__noop_resize(void *ctx, void *buf, size_t size, size_t align, size_t new_size) {
    MEM_NOTUSED(ctx);
    MEM_NOTUSED(buf);
    MEM_NOTUSED(size);
    MEM_NOTUSED(align);
    MEM_NOTUSED(new_size);

    return false;
}

MEMUTIL void mem__noop_dealloc(void *ctx, void *buf, size_t size, size_t align) {
    MEM_NOTUSED(ctx);
    MEM_NOTUSED(buf);
    MEM_NOTUSED(size);
    MEM_NOTUSED(align);
}

MEMIMPL void *alloc_raw(const allocator_t *allocator, const size_t size, const size_t align) {
    MEM_ASSERT(allocator != NULL);
    MEM_ASSERT(allocator->vtable != NULL);
    MEM_ASSERT(size > 0);
    MEM_ASSERT(mem__align_is_valid(align));

    return allocator->vtable->_alloc(allocator->ctx, size, align);
}

MEMIMPL bool resize_raw(const allocator_t *allocator, void *buf, const size_t size, const size_t align,
                        const size_t new_size) {
    MEM_ASSERT(allocator != NULL);
    MEM_ASSERT(allocator->vtable != NULL);
    MEM_ASSERT(buf != NULL);
    MEM_ASSERT(mem__align_is_valid(align));

    if (new_size == 0) {
        dealloc_raw(allocator->ctx, buf, size, align);
        return true;
    }

    if (size == 0) {
        return false;
    }

    if (new_size == size) {
        return true;
    }

    return allocator->vtable->_resize(allocator->ctx, buf, size, align, new_size);
}

MEMIMPL void dealloc_raw(const allocator_t *allocator, void *buf, const size_t size, const size_t align) {
    MEM_ASSERT(allocator != NULL);
    MEM_ASSERT(allocator->vtable != NULL);
    MEM_ASSERT(buf != NULL);
    MEM_ASSERT(mem__align_is_valid(align));

    if (size == 0) {
        return;
    }

    allocator->vtable->_dealloc(allocator->ctx, buf, size, align);
}

// ----- LIBC allocator -----

#ifdef MEM_DEBUG
#define MEM_POISON_BYTE 0xCC
#define MEM_ALLOC_BYTE 0xAA
#define MEM_FREED_BYTE 0xDD

MEMUTIL void mem__mark_as_poisoned(void *s, size_t n) {
    memset(s, MEM_POISON_BYTE, n);
}

MEMUTIL void mem__mark_as_allocated(void *s, size_t n) {
    memset(s, MEM_ALLOC_BYTE, n);
}

MEMUTIL void mem__mark_as_freed(void *s, size_t n) {
    memset(s, MEM_FREED_BYTE, n);
}

MEMUTIL bool mem__is_poisoned(const void *s, size_t n) {
    const unsigned char *p = s;

    while (n-- > 0) {
        if (*p != MEM_POISON_BYTE) {
            return false;
        }
        p++;
    }
    return true;
}
#endif

typedef struct {
    alignas(max_align_t)
#ifdef MEM_DEBUG
    mem__u32 guard_start;
#endif
    void *raw_memory;
    size_t total_size;
#ifdef MEM_DEBUG
    void *data_memory;
    size_t requested_size;
    size_t alignment;
    mem__u32 guard_end;
#endif
} mem__libc_header_t;

#ifdef MEM_DEBUG
#if MEM_BIG_ENDIAN
#define MEM_GUARD_PATTERN 0xDEADBEEF
#else
#define MEM_GUARD_PATTERN 0xEFBEADDE
#endif

MEMUTIL void mem__libc_header_guard(mem__libc_header_t *header) {
    header->guard_start = MEM_GUARD_PATTERN;
    header->guard_end = MEM_GUARD_PATTERN;
}

MEMUTIL bool mem__libc_header_is_guarded(const mem__libc_header_t *header) {
    return header->guard_start == MEM_GUARD_PATTERN && header->guard_end == MEM_GUARD_PATTERN;
}
#endif

MEMUTIL mem__libc_header_t *mem__libc_header_get(const void *buf) {
    return (mem__libc_header_t *) mem__align_backward((mem__uptr) buf - sizeof(mem__libc_header_t),
                                                      alignof(mem__libc_header_t));
}

MEMUTIL void *mem__libc_allocator_alloc(void *ctx, size_t size, size_t align) {
    MEM_NOTUSED(ctx);

    MEM_ASSERT(ctx == NULL);
    MEM_ASSERT(size > 0);
    MEM_ASSERT(mem__align_is_valid(align));

#ifdef PREFER_LIBC_ALIGNED_ALLOC
    void *raw_memory = aligned_alloc(align, size);
    if (raw_memory == NULL) {
        return NULL;
    }

    return raw_memory;
#else
    const size_t header_size = sizeof(mem__libc_header_t);

    const size_t header_padding = alignof(mem__libc_header_t) - 1;
    const size_t data_padding = align - 1;

    const size_t total_size = header_padding + header_size + data_padding + size;

    void *raw_memory = malloc(total_size);
    if (raw_memory == NULL) {
        return NULL;
    }

    const mem__uptr base_header_address = mem__align_forward((mem__uptr) raw_memory, alignof(mem__libc_header_t));
    const mem__uptr data_address = mem__align_forward(base_header_address + header_size, align);
    void *data_memory = (void *) data_address;

    mem__libc_header_t *header = mem__libc_header_get(data_memory);
    header->raw_memory = raw_memory;
    header->total_size = total_size;

#ifdef MEM_DEBUG
    header->data_memory = data_memory;
    header->requested_size = size;
    header->alignment = align;
    mem__libc_header_guard(header);

    mem__mark_as_poisoned(raw_memory, (mem__uptr) header - (mem__uptr) raw_memory);

    const mem__uptr header_end = (mem__uptr) header + header_size;
    mem__mark_as_poisoned((void *) header_end, data_address - header_end);

    mem__mark_as_allocated(data_memory, size);

    const mem__uptr data_end = data_address + size;
    mem__mark_as_poisoned((void *) data_end, ((mem__uptr) raw_memory + total_size) - data_end);
#endif

    return data_memory;
#endif
}

MEMUTIL bool mem__libc_allocator_resize(void *ctx, void *buf, size_t size, size_t align, size_t new_size) {
    MEM_NOTUSED(ctx);
    MEM_NOTUSED(align);

    MEM_ASSERT(ctx == NULL);
    MEM_ASSERT(buf != NULL);
    MEM_ASSERT(size > 0);
    MEM_ASSERT(new_size > 0);
    MEM_ASSERT(size != new_size);
    MEM_ASSERT(size != new_size);
    MEM_ASSERT(mem__align_is_valid(align));

    if (new_size > size) {
        // TODO: We could consider enabling growing to fill excess bytes on the right of data between requested_size and total_size allocated for aligning.
        return false;
    }

#if !defined(PREFER_LIBC_ALIGNED_ALLOC) && defined(MEM_DEBUG)
    mem__libc_header_t *header = mem__libc_header_get(buf);
    header->requested_size = new_size;

    const mem__uptr data_end = (mem__uptr) buf + new_size;
    mem__mark_as_poisoned((void *) data_end, size - new_size);
#endif

    return true;
}

MEMUTIL void mem__libc_allocator_dealloc(void *ctx, void *buf, size_t size, size_t align) {
    MEM_NOTUSED(ctx);
    MEM_NOTUSED(size);
    MEM_NOTUSED(align);

    MEM_ASSERT(ctx == NULL);
    MEM_ASSERT(buf != NULL);
    MEM_ASSERT(size > 0);
    MEM_ASSERT(mem__align_is_valid(align));

#ifdef PREFER_LIBC_ALIGNED_ALLOC
    free(buf);
#else
    const mem__libc_header_t *header = mem__libc_header_get(buf);
    void *raw_memory = header->raw_memory;
#ifdef MEM_DEBUG
    MEM_ASSERT(mem__libc_header_is_guarded(header));

    MEM_ASSERT(mem__is_poisoned(raw_memory, (mem__uptr) header - (mem__uptr) raw_memory));

    const mem__uptr header_end = (mem__uptr) header + sizeof(mem__libc_header_t);
    MEM_ASSERT(mem__is_poisoned((void *) header_end, (mem__uptr) buf - header_end));

    const mem__uptr data_end = (mem__uptr) buf + header->requested_size;
    MEM_ASSERT(mem__is_poisoned((void *) data_end, ((mem__uptr) raw_memory + header->total_size) - data_end));

    mem__mark_as_freed(header->raw_memory, header->total_size);
#endif
    free(raw_memory);
#endif
}

MEMUTIL const allocator_vtable_t mem__libc_allocator_vtable = {
    ._alloc = mem__libc_allocator_alloc,
    ._resize = mem__libc_allocator_resize,
    ._dealloc = mem__libc_allocator_dealloc
};

MEMUTIL const allocator_t mem__libc_allocator = {
    .ctx = NULL,
    .vtable = &mem__libc_allocator_vtable
};

const allocator_t libc_allocator = mem__libc_allocator;

// ----- LOGGING allocator -----

MEMUTIL void *mem__logging_allocator_alloc(void *ctx, size_t size, size_t align) {
    MEM_ASSERT(ctx != NULL);
    MEM_ASSERT(size > 0);
    MEM_ASSERT(mem__align_is_valid(align));

    const logging_allocator_t *logging = ctx;
    MEM_ASSERT(logging->wrapped != NULL);
    MEM_ASSERT(logging->success_file != NULL);
    MEM_ASSERT(logging->failure_file != NULL);

    void *ptr = alloc_raw(logging->wrapped, size, align);

    if (ptr != NULL) {
        fprintf(logging->success_file,
                "alloc - success - size: %zu, align: %zu\n", size, align);
    } else {
        fprintf(logging->failure_file,
                "alloc - failure - size: %zu, align: %zu\n", size, align);
    }

    return ptr;
}

MEMUTIL bool mem__logging_allocator_resize(void *ctx, void *buf, size_t size, size_t align, size_t new_size) {
    MEM_ASSERT(ctx != NULL);
    MEM_ASSERT(buf != NULL);
    MEM_ASSERT(size > 0);
    MEM_ASSERT(new_size > 0);
    MEM_ASSERT(size != new_size);
    MEM_ASSERT(mem__align_is_valid(align));

    const logging_allocator_t *logging = ctx;
    MEM_ASSERT(logging->wrapped != NULL);
    MEM_ASSERT(logging->success_file != NULL);
    MEM_ASSERT(logging->failure_file != NULL);

    const bool success = resize_raw(logging->wrapped, buf, size, align, new_size);

    if (success) {
        fprintf(logging->success_file,
                "resize - success - size: %zu, new_size: %zu, align: %zu\n", size, new_size, align);
    } else {
        fprintf(logging->failure_file,
                "resize - failure - size: %zu, new_size: %zu, align: %zu\n", size, new_size, align);
    }

    return success;
}

MEMUTIL void mem__logging_allocator_dealloc(void *ctx, void *buf, size_t size, size_t align) {
    MEM_ASSERT(ctx != NULL);
    MEM_ASSERT(buf != NULL);
    MEM_ASSERT(size > 0);
    MEM_ASSERT(mem__align_is_valid(align));

    const logging_allocator_t *logging = ctx;
    MEM_ASSERT(logging->wrapped != NULL);
    MEM_ASSERT(logging->success_file != NULL);
    MEM_ASSERT(logging->failure_file != NULL);

    dealloc_raw(logging->wrapped, buf, size, align);

    fprintf(logging->failure_file,
            "free - success - size: %zu, align: %zu\n", size, align);
}

MEMUTIL const allocator_vtable_t mem__logging_allocator_vtable = {
    ._alloc = mem__logging_allocator_alloc,
    ._resize = mem__logging_allocator_resize,
    ._dealloc = mem__logging_allocator_dealloc
};

MEMIMPL logging_allocator_t logging_allocator_init(const allocator_t *wrapped, FILE *success_file, FILE *failure_file) {
    MEM_ASSERT(wrapped != NULL);
    MEM_ASSERT(success_file != NULL);
    MEM_ASSERT(failure_file != NULL);

    return (logging_allocator_t){
        .wrapped = wrapped,
        .success_file = success_file,
        .failure_file = failure_file
    };
}

MEMIMPL logging_allocator_t logging_allocator_init_default(const allocator_t *wrapped) {
    MEM_ASSERT(wrapped != NULL);

    return (logging_allocator_t){
        .wrapped = wrapped,
        .success_file = stdout,
        .failure_file = stderr
    };
}

MEMIMPL allocator_t logging_allocator_to_allocator(logging_allocator_t *ctx) {
    MEM_ASSERT(ctx != NULL);

    return (allocator_t){
        .ctx = ctx,
        .vtable = &mem__logging_allocator_vtable
    };
}

// ----- ARENA allocator -----

MEMUTIL void *mem__arena_allocator_alloc(void *ctx, size_t size, size_t align) {
    MEM_ASSERT(ctx != NULL);
    MEM_ASSERT(size > 0);
    MEM_ASSERT(mem__align_is_valid(align));

    arena_allocator_t *arena = ctx;
    MEM_ASSERT(arena->buf != NULL);
    MEM_ASSERT(arena->size > 0);

    const mem__uptr buf_address = (mem__uptr) arena->buf;
    const mem__uptr current_address = buf_address + arena->end;

    const mem__uptr aligned_address = mem__align_forward(current_address, align);

    const size_t new_end = (aligned_address + size) - buf_address;

    if (new_end > arena->size) {
        return NULL;
    }

    arena->end = new_end;
    return (void *) aligned_address;
}

MEMUTIL const allocator_vtable_t mem__arena_allocator_vtable = {
    ._alloc = mem__arena_allocator_alloc,
    ._resize = mem__noop_resize,
    ._dealloc = mem__noop_dealloc
};

MEMIMPL arena_allocator_t arena_allocator_init(void *buf, const size_t size) {
    MEM_ASSERT(buf != NULL);
    MEM_ASSERT(size > 0);

    return (arena_allocator_t){
        .buf = buf,
        .size = size,
        .end = 0
    };
}

MEMIMPL allocator_t arena_allocator_to_allocator(arena_allocator_t *ctx) {
    MEM_ASSERT(ctx != NULL);

    return (allocator_t){
        .ctx = ctx,
        .vtable = &mem__arena_allocator_vtable
    };
}

MEMIMPL void arena_allocator_reset(arena_allocator_t *ctx) {
    MEM_ASSERT(ctx != NULL);

    ctx->end = 0;
}

#endif
