# Makefile for BrownDust II DLL Dumper
# Usage: make

CXX = x86_64-w64-mingw32-g++
CC = x86_64-w64-mingw32-gcc
CXXFLAGS = -std=c++11 -O2 -Wall
CFLAGS = -O2 -Wall
LDFLAGS = -static-libgcc -static-libstdc++ -s

# MinHook paths
MINHOOK_DIR = ./minhook
MINHOOK_INCLUDE = $(MINHOOK_DIR)/include
MINHOOK_SRC = $(wildcard $(MINHOOK_DIR)/src/*.c) $(wildcard $(MINHOOK_DIR)/src/hde/*.c)
MINHOOK_OBJ = $(MINHOOK_SRC:.c=.o)

# Targets
DLL_TARGET = DumpDll.dll
DECRYPT_DLL_TARGET = DumpDecrypt.dll
EXE_TARGET = Injector.exe

# Source files
DLL_SRC = DumpDll.cpp
DECRYPT_DLL_SRC = DumpDecrypt.cpp
EXE_SRC = Injector.cpp

.PHONY: all clean check

all: check $(DLL_TARGET) $(DECRYPT_DLL_TARGET) $(EXE_TARGET)
	@echo ""
	@echo "================================"
	@echo "Build completed successfully!"
	@echo "================================"
	@echo ""
	@echo "Generated files:"
	@echo "  - $(DLL_TARGET)"
	@echo "  - $(DECRYPT_DLL_TARGET)"
	@echo "  - $(EXE_TARGET)"
	@echo ""

check:
	@if [ ! -d "$(MINHOOK_INCLUDE)" ]; then \
		echo "Error: MinHook not found!"; \
		echo "Clone from: https://github.com/TsudaKageyu/minhook.git"; \
		echo "Place in ./minhook/"; \
		exit 1; \
	fi

$(DLL_TARGET): $(DLL_SRC) $(MINHOOK_OBJ)
	@echo "Compiling $(DLL_TARGET)..."
	$(CXX) -shared -o $@ $(DLL_SRC) $(MINHOOK_OBJ) \
		$(CXXFLAGS) \
		-I$(MINHOOK_INCLUDE) \
		$(LDFLAGS)
	@echo "$(DLL_TARGET) compiled"

$(DECRYPT_DLL_TARGET): $(DECRYPT_DLL_SRC) $(MINHOOK_OBJ)
	@echo "Compiling $(DECRYPT_DLL_TARGET)..."
	$(CXX) -shared -o $@ $(DECRYPT_DLL_SRC) $(MINHOOK_OBJ) \
		$(CXXFLAGS) \
		-I$(MINHOOK_INCLUDE) \
		$(LDFLAGS)
	@echo "$(DECRYPT_DLL_TARGET) compiled"

$(MINHOOK_DIR)/src/%.o: $(MINHOOK_DIR)/src/%.c
	$(CC) -c -o $@ $< $(CFLAGS) -I$(MINHOOK_INCLUDE)

$(MINHOOK_DIR)/src/hde/%.o: $(MINHOOK_DIR)/src/hde/%.c
	$(CC) -c -o $@ $< $(CFLAGS) -I$(MINHOOK_INCLUDE)

$(EXE_TARGET): $(EXE_SRC)
	@echo "Compiling $(EXE_TARGET)..."
	$(CXX) -o $@ $< \
		$(CXXFLAGS) \
		$(LDFLAGS)
	@echo "$(EXE_TARGET) compiled"

clean:
	rm -f $(DLL_TARGET) $(DECRYPT_DLL_TARGET) $(EXE_TARGET) $(MINHOOK_OBJ)
	@echo "Cleaned build files"

install: all
	@echo "Files ready to use!"
	@echo "Run: ./$(EXE_TARGET)"
