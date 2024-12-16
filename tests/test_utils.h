#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <setjmp.h>
#include <stdbool.h>
#include <stddef.h>

extern jmp_buf assert_jump;
extern volatile int assert_count;

extern void assert_count_reset(void);

extern bool is_aligned(const void *ptr, size_t alignment);

#endif
