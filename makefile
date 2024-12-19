# Compiler and tools
CC = gcc
RM = rm -rf
VALGRIND = valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --error-exitcode=1

# Directories and files
TEST_DIR = tests
BIN_DIR = bin
TEST_BIN_DIR = $(BIN_DIR)/tests
HEADER = mem.h
TEST_IMPL = $(TEST_DIR)/test_utils.c

# Test files
TEST_SOURCES = $(filter-out $(TEST_IMPL), $(wildcard $(TEST_DIR)/*.c))
TEST_BINARIES = $(TEST_SOURCES:$(TEST_DIR)/%.c=$(TEST_BIN_DIR)/%)

# Common flags
WARNINGS = -Wall -Wextra -Wpedantic -Werror -Wno-unused-parameter -Wno-unused-function
COMMON_FLAGS = -std=c11 $(WARNINGS)

# Flags
# Build type flags
CFLAGS_DEBUG = $(COMMON_FLAGS) -O0 -g -DDEBUG
CFLAGS_RELEASE = $(COMMON_FLAGS) -O3 -DNDEBUG
CFLAGS ?= $(CFLAGS_DEBUG)  # Default to debug build

# Dependency generation
DEPFLAGS = -MMD -MP
DEPS = $(TEST_BINARIES:=.d)

# Default target
all: test

# Ensure output directories exist
$(TEST_BIN_DIR):
	mkdir -p $@

# Compile test binaries, linking with the STB implementation
$(TEST_BIN_DIR)/%: $(TEST_DIR)/%.c $(TEST_IMPL) $(HEADER) | $(TEST_BIN_DIR)
	$(CC) $(CFLAGS) $(DEPFLAGS) -o $@ $< $(TEST_IMPL)

# Debug and release targets
debug: CFLAGS = $(CFLAGS_DEBUG)
debug: test

release: CFLAGS = $(CFLAGS_RELEASE)
release: test

# Run tests
test: $(TEST_BINARIES)
ifdef TEST
	@echo "Running test $(TEST)..."
	@$(TEST_BIN_DIR)/$(TEST) || exit 1
	@echo "Test passed!"
else
	@echo "Running all tests..."
	@for test in $(TEST_BINARIES); do \
		echo "Running $$test..."; \
		$$test || exit 1; \
	done
	@echo "All tests passed!"
endif

# Run tests with Valgrind
test-valgrind: $(TEST_BINARIES)
ifdef TEST
	@echo "Running test $(TEST) with Valgrind..."
	@$(VALGRIND) $(TEST_BIN_DIR)/$(TEST) || exit 1
else
	@echo "Running all tests with Valgrind..."
	@for test in $(TEST_BINARIES); do \
		echo "Running Valgrind on $$test..."; \
		$(VALGRIND) $$test || exit 1; \
	done
	@echo "All Valgrind tests passed!"
endif

# Clean rules
clean:
	$(RM) $(BIN_DIR)

# Include generated dependencies
-include $(DEPS)

.PHONY: all debug release test test-valgrind clean
