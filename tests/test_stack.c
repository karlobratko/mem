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
    stack_allocator_t stack = stack_allocator_init(buffer, sizeof(buffer));
    allocator_t allocator = stack_allocator_to_allocator(&stack);
    
    void* ptr = alloc_raw(&allocator, 8, 8);
    assert(ptr != NULL);
    assert(is_aligned(ptr, 8));
    memset(ptr, TEST_BYTE, 8);
    
    dealloc_raw(&allocator, ptr, 8, 8);
}

void test_multiple_allocations_lifo(void) {
    printf("test_multiple_allocations_lifo\n");
    
    uint8_t buffer[1024];
    stack_allocator_t stack = stack_allocator_init(buffer, sizeof(buffer));
    allocator_t allocator = stack_allocator_to_allocator(&stack);
    
    void* ptr1 = alloc_raw(&allocator, 4, 4);
    void* ptr2 = alloc_raw(&allocator, 8, 8);
    void* ptr3 = alloc_raw(&allocator, 16, 16);

    assert(ptr1 != NULL && ptr2 != NULL && ptr3 != NULL);

    assert(is_aligned(ptr1, 4));
    assert(is_aligned(ptr2, 8));
    assert(is_aligned(ptr3, 16));

    dealloc_raw(&allocator, ptr3, 16, 16);
    dealloc_raw(&allocator, ptr2, 8, 8);
    dealloc_raw(&allocator, ptr1, 4, 4);
}

void test_alignment_sequence(void) {
    printf("test_alignment_sequence\n");
    
    uint8_t buffer[1024];
    stack_allocator_t stack = stack_allocator_init(buffer, sizeof(buffer));
    allocator_t allocator = stack_allocator_to_allocator(&stack);
    
    void* ptrs[5];
    size_t sizes[] = {8, 16, 32, 16, 8};
    size_t aligns[] = {4, 8, 16, 8, 4};
    
    for (int i = 0; i < 5; i++) {
        ptrs[i] = alloc_raw(&allocator, sizes[i], aligns[i]);
        assert(ptrs[i] != NULL);
        assert(is_aligned(ptrs[i], aligns[i]));
        memset(ptrs[i], TEST_BYTE, sizes[i]);
    }
    
    for (int i = 4; i >= 0; i--) {
        dealloc_raw(&allocator, ptrs[i], sizes[i], aligns[i]);
    }
}

void test_reuse_after_dealloc(void) {
    printf("test_reuse_after_dealloc\n");
    
    uint8_t buffer[1024];
    stack_allocator_t stack = stack_allocator_init(buffer, sizeof(buffer));
    allocator_t allocator = stack_allocator_to_allocator(&stack);
    
    void* ptr1 = alloc_raw(&allocator, 8, 8);
    void* ptr2 = alloc_raw(&allocator, 8, 8);
    uintptr_t original_addr = (uintptr_t)ptr2;

    dealloc_raw(&allocator, ptr2, 8, 8);
    dealloc_raw(&allocator, ptr1, 8, 8);

    void* ptr3 = alloc_raw(&allocator, 8, 8);
    assert(ptr3 == ptr1);
    (void)ptr3;

    void* ptr4 = alloc_raw(&allocator, 8, 8);
    assert((uintptr_t)ptr4 == original_addr);
    (void)ptr4;
    (void)original_addr;
}

void test_reset(void) {
    printf("test_reset\n");

    uint8_t buffer[1024];
    stack_allocator_t stack = stack_allocator_init(buffer, sizeof(buffer));
    allocator_t allocator = stack_allocator_to_allocator(&stack);

    void* ptr1 = alloc_raw(&allocator, 512, 8);
    void* ptr2 = alloc_raw(&allocator, 256, 8);
    assert(ptr1 != NULL && ptr2 != NULL);
    (void) ptr1;
    (void) ptr2;

    stack_allocator_reset(&stack);

    void* ptr3 = alloc_raw(&allocator, 512, 8);
    assert(ptr3 != NULL);
    assert(ptr3 == ptr1);
    (void) ptr3;
}


int main(void) {
    test_basic_allocation();
    test_multiple_allocations_lifo();
    test_alignment_sequence();
    test_reuse_after_dealloc();
    test_reset();

    return EXIT_SUCCESS;
}