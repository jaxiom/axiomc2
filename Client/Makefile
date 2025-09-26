# Cross-compiler for Windows
CXX = x86_64-w64-mingw32-g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -Iinclude
LDFLAGS = -lws2_32 -lwininet -lcrypt32 -static-libgcc -static-libstdc++ -static -liphlpapi -lpsapi -lnetapi32
LDFLAGS += -liphlpapi -lws2_32 -lpsapi

# Directories
SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR = build
BIN_DIR = bin

# Target executable (Windows .exe)
TARGET = $(BIN_DIR)/client.exe

# Find all .cpp files
CORE_SOURCES = $(wildcard $(SRC_DIR)/core/*.cpp)
MODULES_SOURCES = $(wildcard $(SRC_DIR)/modules/*.cpp)
TASKS_SOURCES = $(wildcard $(SRC_DIR)/tasks/*.cpp)
UTILS_SOURCES = $(wildcard $(SRC_DIR)/utils/*.cpp)
MAIN_SOURCE = $(SRC_DIR)/main.cpp

# All sources
SOURCES = $(CORE_SOURCES) $(MODULES_SOURCES) $(TASKS_SOURCES) $(UTILS_SOURCES) $(MAIN_SOURCE)

# Object files
OBJECTS = $(SOURCES:$(SRC_DIR)/%.cpp=$(BUILD_DIR)/%.o)

# Create directories if they don't exist
$(shell mkdir -p $(BUILD_DIR)/core $(BUILD_DIR)/modules $(BUILD_DIR)/tasks $(BUILD_DIR)/utils $(BIN_DIR))

# Default target
all: $(TARGET)

# Link object files to create executable
$(TARGET): $(OBJECTS)
	@echo "Linking $@..."
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS)
	@echo "Build complete: $@"
	@echo "Windows executable created at: $@"

# Compile .cpp files to .o files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	@echo "Compiling $<..."
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
	@echo "Clean complete"

# Rebuild everything
rebuild: clean all

# Debug build
debug: CXXFLAGS += -g -DDEBUG
debug: clean
	@echo "Building DEBUG version with verbose output..."
	@$(MAKE) all

# Install cross-compilation tools
deps:
	sudo apt-get update
	sudo apt-get install -y mingw-w64

# Linux build (for testing on Linux)
linux: CXX = g++
linux: LDFLAGS = -lpthread -lcrypto -lssl
linux: TARGET = $(BIN_DIR)/client_linux
linux: $(TARGET)

.PHONY: all clean rebuild debug deps linux