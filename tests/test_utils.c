#include "test_utils.h"

jmp_buf assert_jump;
volatile int assert_count = 0;

#define MEM_ASSERT(x)            \
do {                             \
    if (!(x)) {                  \
        assert_count++;          \
        longjmp(assert_jump, 1); \
    }                            \
} while(0)

#define MEM_IMPLEMENTATION
#include "../mem.h"

void assert_count_reset(void) {
    assert_count = 0;
}

bool is_aligned(const void *ptr, const size_t alignment) {
    return ((uintptr_t) ptr & (alignment - 1)) == 0;
}
