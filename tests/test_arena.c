#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../mem.h"
#include "test_utils.h"

#define TEST_BYTE 0xBE

void test_alignment_requirements(void) {
    printf("test_alignment_requirements\n");

    uint8_t buffer[512];
    arena_allocator_t arena = arena_allocator_init(buffer, sizeof(buffer));
    allocator_t allocator = arena_allocator_to_allocator(&arena);

    const size_t test_sizes[] = {1, 8, 15, 16, 17, 32, 64, 128};
    const size_t test_aligns[] = {1, 2, 4, 8, 16};

    for (size_t i = 0; i < sizeof(test_sizes)/sizeof(test_sizes[0]); i++) {
        for (size_t j = 0; j < sizeof(test_aligns)/sizeof(test_aligns[0]); j++) {
            const size_t size = test_sizes[i];
            const size_t align = test_aligns[j];

            void* ptr = alloc_raw(&allocator, size, align);
            assert(ptr != NULL);
            assert(is_aligned(ptr, align));

            memset(ptr, TEST_BYTE, size);
            arena_allocator_reset(&arena);
        }
    }
}

void test_out_of_memory(void) {
    printf("test_out_of_memory\n");

    uint8_t small_buffer[16];
    arena_allocator_t arena = arena_allocator_init(small_buffer, sizeof(small_buffer));
    allocator_t allocator = arena_allocator_to_allocator(&arena);

    void* ptr = alloc_raw(&allocator, 32, 8);
    assert(ptr == NULL);

    ptr = alloc_raw(&allocator, 16, 1);
    assert(ptr != NULL);
    (void) ptr;

    void* ptr2 = alloc_raw(&allocator, 1, 1);
    assert(ptr2 == NULL);
    (void)ptr2;
}

void test_reset(void) {
    printf("test_reset\n");

    uint8_t buffer[1024];
    arena_allocator_t arena = arena_allocator_init(buffer, sizeof(buffer));
    allocator_t allocator = arena_allocator_to_allocator(&arena);

    void* ptr1 = alloc_raw(&allocator, 512, 8);
    void* ptr2 = alloc_raw(&allocator, 256, 8);
    assert(ptr1 != NULL && ptr2 != NULL);
    (void) ptr1;
    (void) ptr2;

    arena_allocator_reset(&arena);

    void* ptr3 = alloc_raw(&allocator, 1024, 8);
    assert(ptr3 != NULL);
    assert(ptr3 == ptr1);
    (void) ptr3;
}

int main(void) {
    test_alignment_requirements();
    test_out_of_memory();
    test_reset();

    return EXIT_SUCCESS;
}