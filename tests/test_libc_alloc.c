#include <stddef.h>

#define MEM_IMPLEMENTATION
#include "../mem.h"

#define TEST_BYTE 0xBE

const allocator_t *allocator = &libc_allocator;

static bool is_aligned(const void *ptr, const size_t alignment) {
    return ((uintptr_t) ptr & (alignment - 1)) == 0;
}

void test_alignment_requirements() {
    printf("test_alignment_requirements\n");
    const size_t test_sizes[] = {1, 8, 15, 16, 17, 32, 64, 128};
    const size_t test_aligns[] = {1, 2, 4, 8, 16, 32, 64};

    for (size_t i = 0; i < sizeof(test_sizes) / sizeof(test_sizes[0]); i++) {
        for (size_t j = 0; j < sizeof(test_aligns) / sizeof(test_aligns[0]); j++) {
            const size_t size = test_sizes[i];
            const size_t align = test_aligns[j];

            void *ptr = alloc_raw(allocator, size, align);
            assert(ptr != NULL);
            assert(is_aligned(ptr, align));

            const header_t *header = header_get(ptr);
            assert(header != NULL);
            assert(is_aligned(header, alignof(header)));

            // Verify we can actually write to all the allocated memory
            memset(ptr, TEST_BYTE, size);

            dealloc_raw(allocator, ptr, size, align);
        }
    }
}

void test_memory_layout() {
#ifdef DEBUG
    printf("test_memory_layout\n");
    const size_t size = 16;
    const size_t align = 8;

    void *ptr = alloc_raw(allocator, size, align);
    assert(ptr != NULL);
    assert(is_aligned(ptr, align));

    header_t *header = header_get(ptr);
    assert(header != NULL);
    assert(is_aligned(header, alignof(header_t)));

    // Verify raw memory
    assert(header->raw_memory != NULL);

    // Verify total sizes
    const size_t header_size = sizeof(header_t);
    const size_t header_padding = alignof(header_t) - 1;
    const size_t data_padding = align - 1;
    assert(header->total_size == header_padding + header_size + data_padding + size);

    // Verify guard patterns
    assert(header->guard_start == GUARD_PATTERN);
    assert(header->guard_end == GUARD_PATTERN);

    // Verify sizes
    assert(header->requested_size == size);
    assert(header->alignment == align);

    // Verify memory patterns
    assert(memis(ptr, ALLOC_BYTE, size) == NULL);

    // Calculate regions that should be filled with magic BYTES
    const uintptr_t region_start = (uintptr_t) header->raw_memory;
    const uintptr_t header_start = (uintptr_t) header;
    const uintptr_t header_end = header_start + sizeof(header_t);
    const uintptr_t data_start = (uintptr_t) ptr;
    const uintptr_t data_end = data_start + size;
    const uintptr_t total_end = (uintptr_t) region_start + header->total_size;

    // Check regions
    if (header_start > (uintptr_t) region_start) {
        assert(memis((void*)region_start, POISON_BYTE, header_start - (uintptr_t)region_start) == NULL);
    }

    if (data_start > header_end) {
        assert(memis((void*)header_end, POISON_BYTE,data_start - header_end) == NULL);
    }

    assert(memis((void*)data_start, ALLOC_BYTE, data_end - data_start) == NULL);

    if (total_end > data_end) {
        assert(memis((void*)data_end, POISON_BYTE, total_end - data_end) == NULL);
    }

    dealloc_raw(allocator, ptr, size, align);
#endif
}

int main(void) {
    test_alignment_requirements();
    test_memory_layout();

    return EXIT_SUCCESS;
}
