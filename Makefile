# Compiler and flags
CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -g -Iinclude

# Directories and source files
SRC_CORE    = $(wildcard src/core/*.c)
SRC_PHASE   = $(wildcard src/phase1/*.c)
MAIN_SRC    = src/main.c
COMMON_SRCS = $(SRC_CORE) $(SRC_PHASE)

# Test source files
TEST_FUN_PHASE1_FILE_IO   = tests/functional/phase1/test_file_io.c
TEST_FUN_PHASE1_PHASE1    = tests/functional/phase1/test_phase1.c
TEST_INT_PHASE1_PHASE1    = tests/integration/phase1/test_phase1.c
TEST_UNIT_PHASE1_FILE_IO  = tests/unit/phase1/test_file_io.c
TEST_UNIT_PHASE1_PHASE1   = tests/unit/phase1/test_phase1.c

# Binary directory
BIN_DIR = bin

# Default target: all executables
all: $(BIN_DIR) $(BIN_DIR)/main \
     $(BIN_DIR)/test_fun_phase1_file_io \
     $(BIN_DIR)/test_fun_phase1_phase1 \
     $(BIN_DIR)/test_int_phase1_phase1 \
     $(BIN_DIR)/test_unit_phase1_file_io \
     $(BIN_DIR)/test_unit_phase1_phase1

# Create bin directory if it doesn't exist
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Main executable
$(BIN_DIR)/main: $(MAIN_SRC) $(COMMON_SRCS)
	$(CC) $(CFLAGS) -o $@ $(MAIN_SRC) $(COMMON_SRCS)

# Functional tests
$(BIN_DIR)/test_fun_phase1_file_io: $(TEST_FUN_PHASE1_FILE_IO) $(COMMON_SRCS)
	$(CC) $(CFLAGS) -o $@ $(TEST_FUN_PHASE1_FILE_IO) $(COMMON_SRCS)

$(BIN_DIR)/test_fun_phase1_phase1: $(TEST_FUN_PHASE1_PHASE1) $(COMMON_SRCS)
	$(CC) $(CFLAGS) -o $@ $(TEST_FUN_PHASE1_PHASE1) $(COMMON_SRCS)

# Integration test
$(BIN_DIR)/test_int_phase1_phase1: $(TEST_INT_PHASE1_PHASE1) $(COMMON_SRCS)
	$(CC) $(CFLAGS) -o $@ $(TEST_INT_PHASE1_PHASE1) $(COMMON_SRCS)

# Unit tests
$(BIN_DIR)/test_unit_phase1_file_io: $(TEST_UNIT_PHASE1_FILE_IO) $(COMMON_SRCS)
	$(CC) $(CFLAGS) -o $@ $(TEST_UNIT_PHASE1_FILE_IO) $(COMMON_SRCS)

$(BIN_DIR)/test_unit_phase1_phase1: $(TEST_UNIT_PHASE1_PHASE1) $(COMMON_SRCS)
	$(CC) $(CFLAGS) -o $@ $(TEST_UNIT_PHASE1_PHASE1) $(COMMON_SRCS)

# Clean target
clean:
	rm -rf $(BIN_DIR)

.PHONY: all clean
