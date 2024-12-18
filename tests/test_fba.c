#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../mem.h"
#include "test_utils.h"

#define TEST_BYTE 0xBE

void test_basic_allocation(void) {
    printf("test_basic_allocation\n");
    
    uint8_t buffer[1024];
    fixed_buffer_allocator_t fba = fixed_buffer_allocator_init(buffer, sizeof(buffer));
    allocator_t allocator = fixed_buffer_allocator_to_allocator(&fba);

    void *ptr = alloc_raw(&allocator, 8, 8);
    assert(ptr != NULL);
    assert(is_aligned(ptr, 8));

    memset(ptr, TEST_BYTE, 8);
    
    dealloc_raw(&allocator, ptr, 8, 8);
}

void test_alignment_requirements(void) {
    printf("test_alignment_requirements\n");
    
    uint8_t buffer[1024];
    fixed_buffer_allocator_t fba = fixed_buffer_allocator_init(buffer, sizeof(buffer));
    allocator_t allocator = fixed_buffer_allocator_to_allocator(&fba);
    
    const size_t test_sizes[] = {1, 8, 15, 16, 17, 32, 64, 128};
    const size_t test_aligns[] = {1, 2, 4, 8, 16, 32, 64};

    for (size_t i = 0; i < sizeof(test_sizes)/sizeof(test_sizes[0]); i++) {
        for (size_t j = 0; j < sizeof(test_aligns)/sizeof(test_aligns[0]); j++) {
            const size_t size = test_sizes[i];
            const size_t align = test_aligns[j];
            
            void *ptr = alloc_raw(&allocator, size, align);
            assert(ptr != NULL);
            assert(is_aligned(ptr, align));
            
            memset(ptr, TEST_BYTE, size);
            
            dealloc_raw(&allocator, ptr, size, align);
        }
    }
}

void test_out_of_memory(void) {
    printf("test_out_of_memory\n");
    
    uint8_t small_buffer[16];
    fixed_buffer_allocator_t fba = fixed_buffer_allocator_init(small_buffer, sizeof(small_buffer));
    allocator_t allocator = fixed_buffer_allocator_to_allocator(&fba);

    void *ptr = alloc_raw(&allocator, 32, 8);
    assert(ptr == NULL);

    ptr = alloc_raw(&allocator, 16, 1);
    assert(ptr != NULL);

    void *ptr2 = alloc_raw(&allocator, 1, 1);
    assert(ptr2 == NULL);
}

void test_deallocation(void) {
    printf("test_deallocation\n");
    
    uint8_t buffer[1024];
    fixed_buffer_allocator_t fba = fixed_buffer_allocator_init(buffer, sizeof(buffer));
    allocator_t allocator = fixed_buffer_allocator_to_allocator(&fba);
    
    void *ptr1 = alloc_raw(&allocator, 8, 8);
    void *ptr2 = alloc_raw(&allocator, 8, 8);
    void *ptr3 = alloc_raw(&allocator, 8, 8);
    assert(ptr1 != NULL && ptr2 != NULL && ptr3 != NULL);
    
    dealloc_raw(&allocator, ptr2, 8, 8);
    dealloc_raw(&allocator, ptr3, 8, 8);

    void *ptr4 = alloc_raw(&allocator, 8, 8);
    assert(ptr4 != NULL);

    assert(ptr4 == ptr3);
}

void test_reset(void) {
    printf("test_reset\n");
    
    uint8_t buffer[1024];
    fixed_buffer_allocator_t fba = fixed_buffer_allocator_init(buffer, sizeof(buffer));
    allocator_t allocator = fixed_buffer_allocator_to_allocator(&fba);
    
    void *ptr1 = alloc_raw(&allocator, 512, 8);
    void *ptr2 = alloc_raw(&allocator, 256, 8);
    assert(ptr1 != NULL && ptr2 != NULL);
    
    fixed_buffer_allocator_reset(&fba);
    
    void *ptr3 = alloc_raw(&allocator, 1024, 8);
    assert(ptr3 != NULL);
    assert(ptr3 == ptr1);
}

int main(void) {
    test_basic_allocation();
    test_alignment_requirements();
    test_out_of_memory();
    test_deallocation();
    test_reset();

    return EXIT_SUCCESS;
}