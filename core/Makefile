CXX      ?= g++
CXXFLAGS ?= -O2 -g
CXXFLAGS += -std=c++17 -Wall -Wextra -Wno-unused-parameter -Iinclude -Ithird_party -pthread
BUILD    ?= build

LIB_SRC  := src/types.cpp src/seccomp_filter.cpp src/sandbox.cpp
LIB_OBJ  := $(LIB_SRC:src/%.cpp=$(BUILD)/%.o)
BINS     := $(BUILD)/proctor-init $(BUILD)/proctor-run $(BUILD)/proctord

.PHONY: all clean test
all: $(BINS)

$(BUILD)/%.o: src/%.cpp
	@mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) -MMD -c $< -o $@

$(BUILD)/proctor-init: $(BUILD)/init_main.o $(BUILD)/types.o $(BUILD)/seccomp_filter.o
	$(CXX) $(CXXFLAGS) $^ -o $@

$(BUILD)/proctor-run: $(BUILD)/cli_main.o $(LIB_OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@

$(BUILD)/proctord: $(BUILD)/daemon_main.o $(LIB_OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@

test: all
	python3 tests/run_tests.py $(BUILD)

clean:
	rm -rf $(BUILD)

-include $(wildcard $(BUILD)/*.d)
