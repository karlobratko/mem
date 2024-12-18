#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../mem.h"
#include "test_utils.h"

const allocator_t *allocator = &libc_allocator;

void test_alloc_assertions(void) {
    printf("test_alloc_assertions\n");
    assert_count_reset();

    // Test NULL allocator
    if (setjmp(assert_jump) == 0) {
        alloc_raw(NULL, 8, 8);
        assert(false); // Should not reach here
    }
    assert(assert_count == 1);

    // Test zero size
    if (setjmp(assert_jump) == 0) {
        alloc_raw(allocator, 0, 8);
        assert(false); // Should not reach here
    }
    assert(assert_count == 2);

    // Test invalid alignment
    if (setjmp(assert_jump) == 0) {
        alloc_raw(allocator, 8, 3);
        assert(false); // Should not reach here
    }
    assert(assert_count == 3);
}

void test_resize_assertions(void) {
    printf("test_resize_assertions\n");
    assert_count_reset();

    const size_t size = 8;
    const size_t align = 8;
    const size_t resize_size = 12;

    void *ptr = NULL;
    ptr = alloc_raw(allocator, size, align);
    assert(ptr != NULL);

    // Test NULL allocator
    if (setjmp(assert_jump) == 0) {
        resize_raw(NULL, ptr, size, align, resize_size);
        assert(false); // Should not reach here
    }
    assert(assert_count == 1);

    // Test NULL buffer
    if (setjmp(assert_jump) == 0) {
        resize_raw(allocator, NULL, size, align, resize_size);
        assert(false); // Should not reach here
    }
    assert(assert_count == 2);

    // Test invalid alignment
    if (setjmp(assert_jump) == 0) {
        resize_raw(allocator, ptr, size, 0, resize_size);
        assert(false); // Should not reach here
    }
    assert(assert_count == 3);

    dealloc_raw(allocator, ptr, size, align);
}

void test_dealloc_assertions(void) {
    printf("test_dealloc_assertions\n");
    assert_count_reset();

    const size_t size = 8;
    const size_t align = 8;

    void *ptr = NULL;
    ptr = alloc_raw(allocator, size, align);
    assert(ptr != NULL);

    // Test NULL allocator
    if (setjmp(assert_jump) == 0) {
        dealloc_raw(NULL, ptr, size, align);
        assert(false); // Should not reach here
    }
    assert(assert_count == 1);

    // Test NULL buffer
    if (setjmp(assert_jump) == 0) {
        dealloc_raw(allocator, NULL, size, align);
        assert(false); // Should not reach here
    }
    assert(assert_count == 2);

    // Test invalid alignment
    if (setjmp(assert_jump) == 0) {
        dealloc_raw(allocator, ptr, size, 0);
        assert(false); // Should not reach here
    }
    assert(assert_count == 3);

    dealloc_raw(allocator, ptr, size, align);
}

int main(void) {
    test_alloc_assertions();
    test_resize_assertions();
    test_dealloc_assertions();

    return EXIT_SUCCESS;
}
