#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../mem.h"
#include "test_utils.h"

void test_basic_logging(void) {
    printf("test_basic_logging\n");

    logging_allocator_t logging_allocator = logging_allocator_init_default(&libc_allocator);
    allocator_t allocator = logging_allocator_to_allocator(&logging_allocator);

    void *ptr = alloc_raw(&allocator, 8, 8);
    assert(ptr != NULL);

    dealloc_raw(&allocator, ptr, 8, 8);
}

void test_logging_custom_files(void) {
    printf("test_logging_custom_files\n");

    FILE *success_file = tmpfile();
    assert(success_file != NULL);
    FILE *failure_file = tmpfile();
    assert(failure_file != NULL);

    logging_allocator_t logging_allocator = logging_allocator_init(&libc_allocator, success_file, failure_file);
    allocator_t allocator = logging_allocator_to_allocator(&logging_allocator);

    void *ptrs[3];
    for (int i = 0; i < 3; i++) {
        ptrs[i] = alloc_raw(&allocator, 8, 8);
        assert(ptrs[i] != NULL);
    }

    for (int i = 0; i < 3; i++) {
        dealloc_raw(&allocator, ptrs[i], 8, 8);
    }

    fseek(success_file, 0, SEEK_END);
    long success_size = ftell(success_file);
    assert(success_size > 0);

    fclose(success_file);
    fclose(failure_file);
}

void test_logging_failure(void) {
    printf("test_logging_failure\n");

    uint8_t small_buf[16];
    fixed_buffer_allocator_t fba = fixed_buffer_allocator_init(small_buf, sizeof(small_buf));

    FILE *success_file = tmpfile();
    assert(success_file != NULL);
    FILE *failure_file = tmpfile();
    assert(failure_file != NULL);

    allocator_t fba_allocator = fixed_buffer_allocator_to_allocator(&fba);
    logging_allocator_t logging_allocator = logging_allocator_init(&fba_allocator, success_file, failure_file);
    allocator_t allocator = logging_allocator_to_allocator(&logging_allocator);

    void* ptr = alloc_raw(&allocator, 32, 8);
    assert(ptr == NULL);

    fseek(failure_file, 0, SEEK_END);
    long failure_size = ftell(failure_file);
    assert(failure_size > 0);

    fclose(success_file);
    fclose(failure_file);
}

int main(void) {
    test_basic_logging();
    test_logging_custom_files();
    test_logging_failure();

    return EXIT_SUCCESS;
}
