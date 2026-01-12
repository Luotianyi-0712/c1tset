# Makefile for BrownDust II DLL Dumper
# Usage: make

CXX = x86_64-w64-mingw32-g++
CXXFLAGS = -std=c++11 -O2 -Wall
LDFLAGS = -static-libgcc -static-libstdc++ -s

# MinHook paths
MINHOOK_INCLUDE = ./minhook/include
MINHOOK_LIB = ./minhook/lib
MINHOOK_LINK = -lminhook.x64

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
		echo "Download from: https://github.com/TsudaKageyu/minhook/releases"; \
		echo "Extract to ./minhook/"; \
		exit 1; \
	fi

$(DLL_TARGET): $(DLL_SRC)
	@echo "Compiling $(DLL_TARGET)..."
	$(CXX) -shared -o $@ $< \
		$(CXXFLAGS) \
		-I$(MINHOOK_INCLUDE) \
		-L$(MINHOOK_LIB) \
		$(MINHOOK_LINK) \
		$(LDFLAGS)
	@echo "✓ $(DLL_TARGET) compiled"

$(DECRYPT_DLL_TARGET): $(DECRYPT_DLL_SRC)
	@echo "Compiling $(DECRYPT_DLL_TARGET)..."
	$(CXX) -shared -o $@ $< \
		$(CXXFLAGS) \
		-I$(MINHOOK_INCLUDE) \
		-L$(MINHOOK_LIB) \
		$(MINHOOK_LINK) \
		$(LDFLAGS)
	@echo "$(DECRYPT_DLL_TARGET) compiled"

$(EXE_TARGET): $(EXE_SRC)
	@echo "Compiling $(EXE_TARGET)..."
	$(CXX) -o $@ $< \
		$(CXXFLAGS) \
		$(LDFLAGS)
	@echo "✓ $(EXE_TARGET) compiled"

clean:
	rm -f $(DLL_TARGET) $(DECRYPT_DLL_TARGET) $(EXE_TARGET)
	@echo "Cleaned build files"

install: all
	@echo "Files ready to use!"
	@echo "Run: ./$(EXE_TARGET)"
