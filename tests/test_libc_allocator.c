#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

            // Verify we can actually write to all the allocated memory
            memset(ptr, TEST_BYTE, size);

            dealloc_raw(allocator, ptr, size, align);
        }
    }
}

int main(void) {
    test_alignment_requirements();

    return EXIT_SUCCESS;
}
