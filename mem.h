#ifndef MEM_H
#define MEM_H

#ifndef MEM_DEF
#define MEM_DEF static inline
#endif

#ifndef MEM_EXT
#define MEM_EXT extern
#endif

#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct allocator_t allocator_t;

MEM_DEF void *alloc_raw(const allocator_t *allocator, size_t size, size_t align);

MEM_DEF bool resize_raw(const allocator_t *allocator, void *buf, size_t size, size_t align, size_t new_size);

MEM_DEF void dealloc_raw(const allocator_t *allocator, void *buf, size_t size, size_t align);

#define alloc(allocator, type, len) (alloc_raw((allocator), (sizeof(type) * len), alignof(type)))

#define resize(allocator, type, buf, len, new_len) (resize_raw((allocator), (buf), (sizeof(type) * len), alignof(type), (sizeof(type) * new_len)))

#define dealloc(allocator, type, buf, len) (dealloc_raw((allocator), (buf), (sizeof(type) * len), alignof(type)))

#define create(allocator, type) alloc(allocator, type, 1)

#define destroy(allocator, type, buf) dealloc(allocator, type, buf, 1)

// ----- LIBC allocator -----

MEM_EXT const allocator_t libc_allocator;

// ----- LOGGING allocator -----

typedef struct logging_allocator_t logging_allocator_t;

MEM_DEF logging_allocator_t logging_allocator_init(const allocator_t *wrapped);

MEM_DEF allocator_t logging_allocator_to_allocator(logging_allocator_t *ctx);

// ----- FIXED BUFFER allocator -----

typedef struct fixed_buffer_allocator_t fixed_buffer_allocator_t;

MEM_DEF fixed_buffer_allocator_t fixed_buffer_allocator_init(void *buf, size_t size);

MEM_DEF allocator_t fixed_buffer_allocator_to_allocator(fixed_buffer_allocator_t *ctx);

MEM_DEF void fixed_buffer_allocator_reset(fixed_buffer_allocator_t *ctx);

#endif

#ifdef MEM_IMPLEMENTATION

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(NDEBUG) && !defined(DEBUG)
#define DEBUG
#endif

#ifdef DEBUG
MEM_DEF bool align_is_valid(const size_t align) {
    return align > 0 && (align & (align - 1)) == 0;
}

MEM_DEF uintptr_t align_address(const uintptr_t address, const size_t alignment) {
    return (address + (alignment - 1)) & ~(alignment - 1);
}
#endif

typedef struct {
    void *(*_alloc)(void *ctx, size_t size, size_t align);

    bool (*_resize)(void *ctx, void *buf, size_t size, size_t align, size_t new_size);

    void (*_dealloc)(void *ctx, void *buf, size_t size, size_t align);
} allocator_vtable_t;

struct allocator_t {
    void *ctx;
    const allocator_vtable_t *vtable;
};

MEM_DEF bool no_resize(void *ctx, void *buf, size_t size, size_t align, size_t new_size) {
    (void) ctx;
    (void) buf;
    (void) size;
    (void) align;
    (void) new_size;
    return false;
}

MEM_DEF void no_dealloc(void *ctx, void *buf, size_t size, size_t align) {
    (void) ctx;
    (void) buf;
    (void) size;
    (void) align;
}

MEM_DEF void *alloc_raw(const allocator_t *allocator, const size_t size, const size_t align) {
    assert(allocator != NULL);
    assert(allocator->vtable != NULL);
    assert(size > 0);
    assert(align_is_valid(align));

    return allocator->vtable->_alloc(allocator->ctx, size, align);
}

MEM_DEF bool resize_raw(const allocator_t *allocator, void *buf, const size_t size, const size_t align,
                        const size_t new_size) {
    assert(allocator != NULL);
    assert(allocator->vtable != NULL);
    assert(buf != NULL);
    assert(align_is_valid(align));

    if (new_size == 0) {
        dealloc_raw(allocator->ctx, buf, size, align);
        return true;
    }

    if (size == 0) {
        return false;
    }

    return allocator->vtable->_resize(allocator->ctx, buf, size, align, new_size);
}

MEM_DEF void dealloc_raw(const allocator_t *allocator, void *buf, const size_t size, const size_t align) {
    assert(allocator != NULL);
    assert(allocator->vtable != NULL);
    assert(buf != NULL);
    assert(align_is_valid(align));

    if (size == 0) {
        return;
    }

    allocator->vtable->_dealloc(allocator->ctx, buf, size, align);
}

// ----- LIBC allocator -----

#ifdef DEBUG
#define GUARD_PATTERN 0xDEADBEEF
#define POISON_BYTE 0xCC
#define ALLOC_BYTE 0xAA
#define FREED_BYTE 0xDD
#endif

typedef struct {
    alignas(max_align_t)
#ifdef DEBUG
    uint32_t guard_start;
#endif
    void *raw_memory;
    size_t total_size;
#ifdef DEBUG
    void *data_memory;
    size_t requested_size;
    size_t alignment;
    uint32_t guard_end;
#endif
} header_t;

MEM_DEF header_t *header_get(void *buf) {
    const uintptr_t unaligned_header_address = (uintptr_t) buf - sizeof(header_t);
    const uintptr_t header_address = unaligned_header_address & ~(alignof(header_t) - 1);
    return (header_t *) header_address;
}

MEM_DEF void *_libc_allocator_alloc(void *ctx, size_t size, size_t align) {
    (void) ctx;

    assert(ctx == NULL);
    assert(size > 0);
    assert(align_is_valid(align));

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

    const uintptr_t base_header_address = ((uintptr_t) raw_memory + header_padding) & ~header_padding;
    const uintptr_t data_address = (base_header_address + header_size + data_padding) & ~data_padding;
    void *data_memory = (void *) data_address;

    header_t *header = header_get(data_memory);
    header->raw_memory = raw_memory;
    header->total_size = total_size;

#ifdef DEBUG
    header->guard_start = GUARD_PATTERN;
    header->data_memory = (void *) data_address;
    header->requested_size = size;
    header->alignment = align;
    header->guard_end = GUARD_PATTERN;

    memset(raw_memory, POISON_BYTE, (uintptr_t) header - (uintptr_t) raw_memory);

    const uintptr_t header_end = (uintptr_t) header + header_size;
    memset((void *) header_end, POISON_BYTE, data_address - header_end);

    memset((void *) data_address, ALLOC_BYTE, size);

    const uintptr_t data_end = data_address + size;
    memset((void *) data_end, POISON_BYTE, ((uintptr_t) raw_memory + total_size) - data_end);
#endif

    return data_memory;
#endif
}

#ifdef DEBUG
MEM_DEF void *memis(const void *s, const int c, size_t n) {
    const unsigned char *p = s;
    const unsigned char v = c;

    while (n-- > 0) {
        if (*p != v) {
            return (void *) p;
        }
        p++;
    }
    return NULL;
}
#endif

MEM_DEF void _libc_allocator_dealloc(void *ctx, void *buf, size_t size, size_t align) {
    (void) ctx;
    (void) size;

    assert(ctx == NULL);
    assert(buf != NULL);
    assert(size > 0);
    assert(align_is_valid(align));

#ifdef PREFER_LIBC_ALIGNED_ALLOC
    free(buf);
#else
    const header_t *header = header_get(buf);
    void *raw_memory = header->raw_memory;
#ifdef DEBUG
    assert(header->guard_start == GUARD_PATTERN && header->guard_end == GUARD_PATTERN);

    assert(memis(raw_memory, POISON_BYTE, (uintptr_t) header - (uintptr_t) raw_memory) == NULL);

    const uintptr_t header_end = (uintptr_t) header + sizeof(header_t);
    assert(memis((void *) header_end, POISON_BYTE, (uintptr_t) buf - header_end) == NULL);

    const uintptr_t data_end = (uintptr_t) buf + size;
    assert(memis((void *) data_end, POISON_BYTE, ((uintptr_t) raw_memory + header->total_size) - data_end) == NULL);

    memset(header->raw_memory, FREED_BYTE, header->total_size);
#endif
    free(raw_memory);
#endif
}

static const allocator_vtable_t _libc_allocator_vtable = {
    ._alloc = _libc_allocator_alloc,
    ._resize = no_resize,
    ._dealloc = _libc_allocator_dealloc
};

static const allocator_t _libc_allocator = {
    .ctx = NULL,
    .vtable = &_libc_allocator_vtable
};

const allocator_t libc_allocator = _libc_allocator;

// ----- LOGGING allocator -----

struct logging_allocator_t {
    const allocator_t *wrapped;
};

MEM_DEF void *_logging_allocator_alloc(void *ctx, size_t size, size_t align) {
    assert(ctx != NULL);
    assert(size > 0);
    assert(align_is_valid(align));

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

MEM_DEF bool _logging_allocator_resize(void *ctx, void *buf, size_t size, size_t align, size_t new_size) {
    assert(ctx != NULL);
    assert(buf != NULL);
    assert(align_is_valid(align));

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

MEM_DEF void _logging_allocator_dealloc(void *ctx, void *buf, size_t size, size_t align) {
    assert(ctx != NULL);
    assert(buf != NULL);
    assert(size > 0);
    assert(align_is_valid(align));

    const logging_allocator_t *logging_ctx = ctx;

    printf("[Logging Allocator] Freeing buffer at %p with alignment %zu\n", buf, align);

    dealloc_raw(logging_ctx->wrapped, buf, size, align);

    printf("[Logging Allocator] Free successful\n");
}

static const allocator_vtable_t _logging_allocator_vtable = {
    ._alloc = _logging_allocator_alloc,
    ._resize = _logging_allocator_resize,
    ._dealloc = _logging_allocator_dealloc
};

MEM_DEF logging_allocator_t logging_allocator_init(const allocator_t *wrapped) {
    return (logging_allocator_t){
        .wrapped = wrapped
    };
}

MEM_DEF allocator_t logging_allocator_to_allocator(logging_allocator_t *ctx) {
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

MEM_DEF void *_fixed_buffer_allocator_alloc(void *ctx, size_t size, size_t align) {
    assert(ctx != NULL);
    assert(size > 0);
    assert(align_is_valid(align));

    fixed_buffer_allocator_t *fba_ctx = ctx;

    const uintptr_t buf_address = (uintptr_t) fba_ctx->buf;
    const uintptr_t current_address = buf_address + fba_ctx->end;

    const uintptr_t aligned_address = align_address(current_address, align);

    const size_t new_end = (aligned_address + size) - buf_address;

    if (new_end > fba_ctx->size) {
        return NULL;
    }

    fba_ctx->end = new_end;
    return (void *) aligned_address;
}

MEM_DEF bool _fixed_buffer_allocator_resize(void *ctx, void *buf, size_t size, size_t align, size_t new_size) {
    assert(ctx != NULL);
    assert(buf != NULL);
    assert(align_is_valid(align));

    fixed_buffer_allocator_t *fba_ctx = ctx;

    const uintptr_t fba_next_address = (uintptr_t) fba_ctx->buf + fba_ctx->end;
    const uintptr_t buf_after_address = (uintptr_t) buf + size;

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

MEM_DEF void _fixed_buffer_allocator_dealloc(void *ctx, void *buf, size_t size, size_t align) {
    assert(ctx != NULL);
    assert(buf != NULL);
    assert(size > 0);
    assert(align_is_valid(align));

    fixed_buffer_allocator_t *fba_ctx = ctx;

    const uintptr_t fba_next_address = (uintptr_t) fba_ctx->buf + fba_ctx->end;
    const uintptr_t buf_after_address = (uintptr_t) buf + size;

    if (buf_after_address == fba_next_address) {
        fba_ctx->end -= size;
    }
}

static const allocator_vtable_t _fixed_buffer_allocator_vtable = {
    ._alloc = _fixed_buffer_allocator_alloc,
    ._resize = _fixed_buffer_allocator_resize,
    ._dealloc = _fixed_buffer_allocator_dealloc
};

MEM_DEF fixed_buffer_allocator_t fixed_buffer_allocator_init(void *buf, const size_t size) {
    return (fixed_buffer_allocator_t){
        .buf = buf,
        .size = size,
        .end = 0
    };
}

MEM_DEF allocator_t fixed_buffer_allocator_to_allocator(fixed_buffer_allocator_t *ctx) {
    return (allocator_t){
        .ctx = ctx,
        .vtable = &_fixed_buffer_allocator_vtable
    };
}

MEM_DEF void fixed_buffer_allocator_reset(fixed_buffer_allocator_t *ctx) {
    ctx->end = 0;
}

#endif
