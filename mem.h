#ifndef MEM_H
#define MEM_H

#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>

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

typedef struct allocator_t allocator_t;

MEMAPI void *alloc_raw(const allocator_t *allocator, size_t size, size_t align);

MEMAPI bool resize_raw(const allocator_t *allocator, void *buf, size_t size, size_t align, size_t new_size);

MEMAPI void dealloc_raw(const allocator_t *allocator, void *buf, size_t size, size_t align);

#define alloc(allocator, type, len) (alloc_raw((allocator), (sizeof(type) * len), alignof(type)))

#define resize(allocator, type, buf, len, new_len) (resize_raw((allocator), (buf), (sizeof(type) * len), alignof(type), (sizeof(type) * new_len)))

#define dealloc(allocator, type, buf, len) (dealloc_raw((allocator), (buf), (sizeof(type) * len), alignof(type)))

#define create(allocator, type) alloc(allocator, type, 1)

#define destroy(allocator, type, buf) dealloc(allocator, type, buf, 1)

// ----- LIBC allocator -----

MEMAPI const allocator_t libc_allocator;

// ----- LOGGING allocator -----

typedef struct logging_allocator_t logging_allocator_t;

MEMAPI logging_allocator_t logging_allocator_init(const allocator_t *wrapped);

MEMAPI allocator_t logging_allocator_to_allocator(logging_allocator_t *ctx);

// ----- FIXED BUFFER allocator -----

typedef struct fixed_buffer_allocator_t fixed_buffer_allocator_t;

MEMAPI fixed_buffer_allocator_t fixed_buffer_allocator_init(void *buf, size_t size);

MEMAPI allocator_t fixed_buffer_allocator_to_allocator(fixed_buffer_allocator_t *ctx);

MEMAPI void fixed_buffer_allocator_reset(fixed_buffer_allocator_t *ctx);

#ifdef __cplusplus
}
#endif

#endif

#ifdef MEM_IMPLEMENTATION

#include <stdint.h>
typedef uint32_t mem_u32;
typedef uintptr_t mem_address;

// TODO: LOGGING allocator should support working with custom printing function, not relying on std.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

MEMUTIL bool _align_is_valid(const size_t align) {
    return align > 0 && (align & (align - 1)) == 0;
}

MEMUTIL uintptr_t _address_align(const mem_address address, const size_t alignment) {
    return (address + (alignment - 1)) & ~(alignment - 1);
}

typedef struct {
    void *(*_alloc)(void *ctx, size_t size, size_t align);

    bool (*_resize)(void *ctx, void *buf, size_t size, size_t align, size_t new_size);

    void (*_dealloc)(void *ctx, void *buf, size_t size, size_t align);
} allocator_vtable_t;

struct allocator_t {
    void *ctx;
    const allocator_vtable_t *vtable;
};

MEMUTIL bool _no_resize(void *ctx, void *buf, size_t size, size_t align, size_t new_size) {
    MEM_NOTUSED(ctx);
    MEM_NOTUSED(buf);
    MEM_NOTUSED(size);
    MEM_NOTUSED(align);
    MEM_NOTUSED(new_size);
    return false;
}

MEMUTIL void _no_dealloc(void *ctx, void *buf, size_t size, size_t align) {
    MEM_NOTUSED(ctx);
    MEM_NOTUSED(buf);
    MEM_NOTUSED(size);
    MEM_NOTUSED(align);
}

MEMIMPL void *alloc_raw(const allocator_t *allocator, const size_t size, const size_t align) {
    MEM_ASSERT(allocator != NULL);
    MEM_ASSERT(allocator->vtable != NULL);
    MEM_ASSERT(size > 0);
    MEM_ASSERT(_align_is_valid(align));

    return allocator->vtable->_alloc(allocator->ctx, size, align);
}

MEMIMPL bool resize_raw(const allocator_t *allocator, void *buf, const size_t size, const size_t align,
                        const size_t new_size) {
    MEM_ASSERT(allocator != NULL);
    MEM_ASSERT(allocator->vtable != NULL);
    MEM_ASSERT(buf != NULL);
    MEM_ASSERT(_align_is_valid(align));

    if (new_size == 0) {
        dealloc_raw(allocator->ctx, buf, size, align);
        return true;
    }

    if (size == 0) {
        return false;
    }

    return allocator->vtable->_resize(allocator->ctx, buf, size, align, new_size);
}

MEMIMPL void dealloc_raw(const allocator_t *allocator, void *buf, const size_t size, const size_t align) {
    MEM_ASSERT(allocator != NULL);
    MEM_ASSERT(allocator->vtable != NULL);
    MEM_ASSERT(buf != NULL);
    MEM_ASSERT(_align_is_valid(align));

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

MEMUTIL void _memory_mark_as_poisoned(void *s, size_t n) {
    memset(s, MEM_POISON_BYTE, n);
}

MEMUTIL void _memory_mark_as_allocated(void *s, size_t n) {
    memset(s, MEM_ALLOC_BYTE, n);
}

MEMUTIL void _memory_mark_as_freed(void *s, size_t n) {
    memset(s, MEM_FREED_BYTE, n);
}

MEMUTIL bool _memory_is_poisoned(const void *s, size_t n) {
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
    mem_u32 guard_start;
#endif
    void *raw_memory;
    size_t total_size;
#ifdef MEM_DEBUG
    void *data_memory;
    size_t requested_size;
    size_t alignment;
    mem_u32 guard_end;
#endif
} header_t;

#ifdef MEM_DEBUG
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define MEM_GUARD_PATTERN 0xDEADBEEF
#else
#define MEM_GUARD_PATTERN 0xEFBEADDE
#endif

MEMUTIL void _header_guard(header_t *header) {
    header->guard_start = MEM_GUARD_PATTERN;
    header->guard_end = MEM_GUARD_PATTERN;
}

MEMUTIL bool _header_is_guarded(const header_t *header) {
    return header->guard_start == MEM_GUARD_PATTERN && header->guard_end == MEM_GUARD_PATTERN;
}
#endif

MEMUTIL header_t *_header_get(const void *buf) {
    const mem_address unaligned_header_address = (mem_address) buf - sizeof(header_t);
    const mem_address header_address = unaligned_header_address & ~(alignof(header_t) - 1);
    return (header_t *) header_address;
}

MEMUTIL void *_libc_allocator_alloc(void *ctx, size_t size, size_t align) {
    MEM_NOTUSED(ctx);

    MEM_ASSERT(ctx == NULL);
    MEM_ASSERT(size > 0);
    MEM_ASSERT(_align_is_valid(align));

#ifdef PREFER_LIBC_ALIGNED_ALLOC
    void *raw_memory = aligned_alloc(align, size);
    if (raw_memory == NULL) {
        return NULL;
    }

    return raw_memory;
#else
    const size_t header_size = sizeof(header_t);

    const size_t header_padding = alignof(header_t) - 1;
    const size_t data_padding = align - 1;

    const size_t total_size = header_padding + header_size + data_padding + size;

    void *raw_memory = malloc(total_size);
    if (raw_memory == NULL) {
        return NULL;
    }

    const mem_address base_header_address = _address_align((mem_address) raw_memory, alignof(header_t));
    const mem_address data_address = _address_align(base_header_address + header_size, align);
    void *data_memory = (void *) data_address;

    header_t *header = _header_get(data_memory);
    header->raw_memory = raw_memory;
    header->total_size = total_size;

#ifdef MEM_DEBUG
    header->data_memory = data_memory;
    header->requested_size = size;
    header->alignment = align;
    _header_guard(header);

    _memory_mark_as_poisoned(raw_memory, (mem_address) header - (mem_address) raw_memory);

    const mem_address header_end = (mem_address) header + header_size;
    _memory_mark_as_poisoned((void *) header_end, data_address - header_end);

    _memory_mark_as_allocated(data_memory, size);

    const mem_address data_end = data_address + size;
    _memory_mark_as_poisoned((void *) data_end, ((mem_address) raw_memory + total_size) - data_end);
#endif

    return data_memory;
#endif
}

MEMUTIL void _libc_allocator_dealloc(void *ctx, void *buf, size_t size, size_t align) {
    MEM_NOTUSED(ctx);
    MEM_NOTUSED(size);

    MEM_ASSERT(ctx == NULL);
    MEM_ASSERT(buf != NULL);
    MEM_ASSERT(size > 0);
    MEM_ASSERT(_align_is_valid(align));

#ifdef PREFER_LIBC_ALIGNED_ALLOC
    free(buf);
#else
    const header_t *header = _header_get(buf);
    void *raw_memory = header->raw_memory;
#ifdef MEM_DEBUG
    MEM_ASSERT(_header_is_guarded(header));

    MEM_ASSERT(_memory_is_poisoned(raw_memory, (mem_address) header - (mem_address) raw_memory));

    const mem_address header_end = (mem_address) header + sizeof(header_t);
    MEM_ASSERT(_memory_is_poisoned((void *) header_end, (mem_address) buf - header_end));

    const mem_address data_end = (mem_address) buf + size;
    MEM_ASSERT(_memory_is_poisoned((void *) data_end, ((mem_address) raw_memory + header->total_size) - data_end));

    _memory_mark_as_freed(header->raw_memory, header->total_size);
#endif
    free(raw_memory);
#endif
}

MEMUTIL const allocator_vtable_t _libc_allocator_vtable = {
    ._alloc = _libc_allocator_alloc,
    ._resize = _no_resize,
    ._dealloc = _libc_allocator_dealloc
};

MEMUTIL const allocator_t _libc_allocator = {
    .ctx = NULL,
    .vtable = &_libc_allocator_vtable
};

const allocator_t libc_allocator = _libc_allocator;

// ----- LOGGING allocator -----

struct logging_allocator_t {
    const allocator_t *wrapped;
};

MEMUTIL void *_logging_allocator_alloc(void *ctx, size_t size, size_t align) {
    MEM_ASSERT(ctx != NULL);
    MEM_ASSERT(size > 0);
    MEM_ASSERT(_align_is_valid(align));

    const logging_allocator_t *logging_ctx = ctx;

    printf("[Logging Allocator] Allocating %zu bytes with alignment %zu\n", size, align);

    void *ptr = alloc_raw(logging_ctx->wrapped, size, align);

    if (ptr != NULL) {
        printf("[Logging Allocator] Allocation successful at address %p\n", ptr);
    } else {
        printf("[Logging Allocator] Allocation failed\n");
    }

    return ptr;
}

MEMUTIL bool _logging_allocator_resize(void *ctx, void *buf, size_t size, size_t align, size_t new_size) {
    MEM_ASSERT(ctx != NULL);
    MEM_ASSERT(buf != NULL);
    MEM_ASSERT(_align_is_valid(align));

    const logging_allocator_t *logging_ctx = ctx;

    printf("[Logging Allocator] Resizing buffer at %p to %zu bytes with alignment %zu\n", buf, new_size, align);

    const bool success = resize_raw(logging_ctx->wrapped, buf, size, align, new_size);

    if (success) {
        printf("[Logging Allocator] Resize successful\n");
    } else {
        printf("[Logging Allocator] Resize failed\n");
    }

    return success;
}

MEMUTIL void _logging_allocator_dealloc(void *ctx, void *buf, size_t size, size_t align) {
    MEM_ASSERT(ctx != NULL);
    MEM_ASSERT(buf != NULL);
    MEM_ASSERT(size > 0);
    MEM_ASSERT(_align_is_valid(align));

    const logging_allocator_t *logging_ctx = ctx;

    printf("[Logging Allocator] Freeing buffer at %p with alignment %zu\n", buf, align);

    dealloc_raw(logging_ctx->wrapped, buf, size, align);

    printf("[Logging Allocator] Free successful\n");
}

MEMUTIL const allocator_vtable_t _logging_allocator_vtable = {
    ._alloc = _logging_allocator_alloc,
    ._resize = _logging_allocator_resize,
    ._dealloc = _logging_allocator_dealloc
};

MEMIMPL logging_allocator_t logging_allocator_init(const allocator_t *wrapped) {
    return (logging_allocator_t){
        .wrapped = wrapped
    };
}

MEMIMPL allocator_t logging_allocator_to_allocator(logging_allocator_t *ctx) {
    return (allocator_t){
        .ctx = ctx,
        .vtable = &_logging_allocator_vtable
    };
}

// ----- FIXED BUFFER allocator -----

struct fixed_buffer_allocator_t {
    void *buf;
    const size_t size;
    size_t end;
};

MEMUTIL void *_fixed_buffer_allocator_alloc(void *ctx, size_t size, size_t align) {
    MEM_ASSERT(ctx != NULL);
    MEM_ASSERT(size > 0);
    MEM_ASSERT(_align_is_valid(align));

    fixed_buffer_allocator_t *fba_ctx = ctx;

    const mem_address buf_address = (mem_address) fba_ctx->buf;
    const mem_address current_address = buf_address + fba_ctx->end;

    const mem_address aligned_address = _address_align(current_address, align);

    const size_t new_end = (aligned_address + size) - buf_address;

    if (new_end > fba_ctx->size) {
        return NULL;
    }

    fba_ctx->end = new_end;
    return (void *) aligned_address;
}

MEMUTIL bool _fixed_buffer_allocator_resize(void *ctx, void *buf, size_t size, size_t align, size_t new_size) {
    MEM_ASSERT(ctx != NULL);
    MEM_ASSERT(buf != NULL);
    MEM_ASSERT(_align_is_valid(align));

    fixed_buffer_allocator_t *fba_ctx = ctx;

    const mem_address fba_next_address = (mem_address) fba_ctx->buf + fba_ctx->end;
    const mem_address buf_after_address = (mem_address) buf + size;

    if (buf_after_address != fba_next_address) {
        return new_size <= size;
    }

    if (new_size <= size) {
        const size_t sub = size - new_size;
        fba_ctx->end -= sub;
        return true;
    }

    const size_t add = new_size - size;
    if (add + fba_ctx->end > fba_ctx->size) {
        return false;
    }

    fba_ctx->end += add;
    return true;
}

MEMUTIL void _fixed_buffer_allocator_dealloc(void *ctx, void *buf, size_t size, size_t align) {
    MEM_ASSERT(ctx != NULL);
    MEM_ASSERT(buf != NULL);
    MEM_ASSERT(size > 0);
    MEM_ASSERT(_align_is_valid(align));

    fixed_buffer_allocator_t *fba_ctx = ctx;

    const mem_address fba_next_address = (mem_address) fba_ctx->buf + fba_ctx->end;
    const mem_address buf_after_address = (mem_address) buf + size;

    if (buf_after_address == fba_next_address) {
        fba_ctx->end -= size;
    }
}

MEMUTIL const allocator_vtable_t _fixed_buffer_allocator_vtable = {
    ._alloc = _fixed_buffer_allocator_alloc,
    ._resize = _fixed_buffer_allocator_resize,
    ._dealloc = _fixed_buffer_allocator_dealloc
};

MEMIMPL fixed_buffer_allocator_t fixed_buffer_allocator_init(void *buf, const size_t size) {
    return (fixed_buffer_allocator_t){
        .buf = buf,
        .size = size,
        .end = 0
    };
}

MEMIMPL allocator_t fixed_buffer_allocator_to_allocator(fixed_buffer_allocator_t *ctx) {
    return (allocator_t){
        .ctx = ctx,
        .vtable = &_fixed_buffer_allocator_vtable
    };
}

MEMIMPL void fixed_buffer_allocator_reset(fixed_buffer_allocator_t *ctx) {
    ctx->end = 0;
}

#endif
