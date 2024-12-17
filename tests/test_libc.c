#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../mem.h"
#include "test_utils.h"

#define TEST_BYTE 0xBE

const allocator_t *allocator = &libc_allocator;

void test_common_types(void) {
    printf("test_common_types\n");

    // Test char alignment
    char *c = alloc(allocator, char, 1);
    assert(c != NULL);
    dealloc(allocator, char, c, 1);

    // Test int alignment
    int *i = alloc(allocator, int, 1);
    assert(i != NULL);
    assert(is_aligned(i, alignof(int)));
    dealloc(allocator, int, i, 1);

    // Test double alignment
    double *d = alloc(allocator, double, 1);
    assert(d != NULL);
    assert(is_aligned(d, alignof(double)));
    dealloc(allocator, double, d, 1);
}

void test_mixed_alignments(void) {
    printf("test_mixed_alignments\n");

    // Test allocation where data alignment > header alignment
    void *ptr1 = alloc_raw(allocator, 8, 64);
    assert(ptr1 != NULL);
    assert(is_aligned(ptr1, 64));
    dealloc_raw(allocator, ptr1, 8, 64);

    // Test max alignment supported on platform
    void *ptr2 = alloc_raw(allocator, 8, alignof(max_align_t));
    assert(ptr2 != NULL);
    assert(is_aligned(ptr2, alignof(max_align_t)));
    dealloc_raw(allocator, ptr2, 8, alignof(max_align_t));
}

void test_alignment_requirements(void) {
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

            // Verify we can actually write to all the allocated memory
            memset(ptr, TEST_BYTE, size);

            dealloc_raw(allocator, ptr, size, align);
        }
    }
}

void test_multiple_allocations(void) {
    printf("test_multiple_allocations\n");
    const size_t count = 100;
    void *ptrs[100];

    // Allocate many blocks
    for (size_t i = 0; i < count; i++) {
        ptrs[i] = alloc_raw(allocator, i + 1, 8);
        assert(ptrs[i] != NULL);
        assert(is_aligned(ptrs[i], 8));
        memset(ptrs[i], TEST_BYTE, i + 1);
    }

    // Deallocate in reverse order
    for (size_t i = count; i > 0; i--) {
        dealloc_raw(allocator, ptrs[i - 1], i, 8);
    }
}

void test_extreme_sizes(void) {
    printf("test_extreme_sizes\n");

    const size_t large_size = 1024 * 1024; // 1MB
    void *large_ptr = alloc_raw(allocator, large_size, 8);
    if (large_ptr != NULL) {
        memset(large_ptr, TEST_BYTE, large_size);
        dealloc_raw(allocator, large_ptr, large_size, 8);
    }

    for (size_t i = 0; i < 1000; i++) {
        const size_t tiny_size = 1;
        void *tiny_ptr = alloc_raw(allocator, tiny_size, 8);
        assert(tiny_ptr != NULL);
        memset(tiny_ptr, TEST_BYTE, tiny_size);
        dealloc_raw(allocator, tiny_ptr, tiny_size, 8);
    }
}

void test_resize_behavior(void) {
    printf("test_resize_behavior\n");
    void *ptr = alloc_raw(allocator, 8, 8);
    assert(ptr != NULL);

    // LIBC allocator doesn't support resize, should return false
    const bool resize_result = resize_raw(allocator, ptr, 8, 8, 16);
    assert(resize_result == false);

    dealloc_raw(allocator, ptr, 8, 8);
}

int main(void) {
    test_common_types();
    test_mixed_alignments();
    test_alignment_requirements();
    test_multiple_allocations();
    test_extreme_sizes();
    test_resize_behavior();

    return EXIT_SUCCESS;
}
