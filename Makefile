# Variables du compilateur
CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -g -Iinclude

# Répertoires sources
SRC_CORE    = $(wildcard src/core/*.c)
SRC_PHASE   = $(wildcard src/phase/*.c)
MAIN_SRC    = src/main.c
COMMON_SRCS = $(SRC_CORE) $(SRC_PHASE)

# Fichiers sources des tests
TEST_FUN_PHASE1_FILE_IO   = tests/functional/phase1/test_file_io.c
TEST_FUN_PHASE1_PHASE1    = tests/functional/phase1/test_phase1.c
TEST_INT_PHASE1_PHASE1    = tests/integration/phase1/test_phase1.c
TEST_UNIT_PHASE1_FILE_IO  = tests/unit/phase1/test_file_io.c
TEST_UNIT_PHASE1_PHASE1   = tests/unit/phase1/test_phase1.c

# Répertoire de destination des exécutables
BIN_DIR = bin

# Cible par défaut : compiler main et tous les tests
all: $(BIN_DIR) $(BIN_DIR)/main \
     $(BIN_DIR)/test_fun_phase1_file_io \
     $(BIN_DIR)/test_fun_phase1_phase1 \
     $(BIN_DIR)/test_int_phase1_phase1 \
     $(BIN_DIR)/test_unit_phase1_file_io \
     $(BIN_DIR)/test_unit_phase1_phase1

# Créer le dossier bin uniquement s'il n'existe pas (compatible Windows)
$(BIN_DIR):
	if not exist $(BIN_DIR) mkdir $(BIN_DIR)

# Exécutable principal
$(BIN_DIR)/main: $(MAIN_SRC) $(COMMON_SRCS)
	$(CC) $(CFLAGS) -o $@ $(MAIN_SRC) $(COMMON_SRCS)

# Test fonctionnel : file_io
$(BIN_DIR)/test_fun_phase1_file_io: $(TEST_FUN_PHASE1_FILE_IO) $(COMMON_SRCS)
	$(CC) $(CFLAGS) -o $@ $(TEST_FUN_PHASE1_FILE_IO) $(COMMON_SRCS)

# Test fonctionnel : phase1
$(BIN_DIR)/test_fun_phase1_phase1: $(TEST_FUN_PHASE1_PHASE1) $(COMMON_SRCS)
	$(CC) $(CFLAGS) -o $@ $(TEST_FUN_PHASE1_PHASE1) $(COMMON_SRCS)

# Test d'intégration : phase1
$(BIN_DIR)/test_int_phase1_phase1: $(TEST_INT_PHASE1_PHASE1) $(COMMON_SRCS)
	$(CC) $(CFLAGS) -o $@ $(TEST_INT_PHASE1_PHASE1) $(COMMON_SRCS)

# Test unitaire : file_io
$(BIN_DIR)/test_unit_phase1_file_io: $(TEST_UNIT_PHASE1_FILE_IO) $(COMMON_SRCS)
	$(CC) $(CFLAGS) -o $@ $(TEST_UNIT_PHASE1_FILE_IO) $(COMMON_SRCS)

# Test unitaire : phase1
$(BIN_DIR)/test_unit_phase1_phase1: $(TEST_UNIT_PHASE1_PHASE1) $(COMMON_SRCS)
	$(CC) $(CFLAGS) -o $@ $(TEST_UNIT_PHASE1_PHASE1) $(COMMON_SRCS)

# Cible de nettoyage
clean:
	rmdir /S /Q $(BIN_DIR)

.PHONY: all clean
