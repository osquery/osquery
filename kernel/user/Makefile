# OS X kext testing makefile
VERSION:=$(shell git describe --tags HEAD --always)
VERSION_DEFINE:=-DVERSION="\"$(VERSION)\""

CXX:=clang++
SHELL:=/bin/bash

USER_INCLUDE_DIR:=include/
USER_INCLUDES:=$(wildcard $(USER_INCLUDE_DIR)*.h)
USER_INCLUDE:=-I$(USER_INCLUDE_DIR)
KERNEL_INCLUDE_DIR:=../include/
KERNEL_INCLUDES:=$(wildcard $(KERNEL_INCLUDE_DIR)*.h)
KERNEL_INCLUDE:=-I$(KERNEL_INCLUDE_DIR)
INCLUDES:=$(USER_INCLUDES) $(KERNEL_INCLUDES)
INCLUDE:=$(USER_INCLUDE) $(KERNEL_INCLUDE)

CXXFLAGS:=$(INCLUDE) $(VERSION_DEFINE) -DDEBUG
LDFLAGS:=

SOURCE_DIR:=src/
TEST_DIR:=test/
BUILD_DIR:=../build/

TEST_SOURCES:=$(wildcard $(TEST_DIR)*.cpp)
CXXSOURCES:=$(wildcard $(SOURCE_DIR)*.cpp)
SOURCES:=$(CXXSORUCES) $(TEST_SOURCES)
CXXOBJECTS:= $(addprefix $(BUILD_DIR), $(notdir $(CXXSOURCES:.cpp=.cpp.o)))
OBJECTS:= $(addprefix $(BUILD_DIR), $(notdir $(TEST_SORUCES:.cpp=.cpp.o))) \
  $(CXXOBJECTS)

EXECUTABLES:=$(addprefix $(BUILD_DIR), $(notdir $(TEST_SOURCES:.cpp=.out)))


.PHONY: all
all: $(EXECUTABLES)

$(BUILD_DIR)%.cpp.o: $(TEST_DIR)%.cpp $(INCLUDES)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)%.cpp.o: $(SOURCE_DIR)%.cpp $(INCLUDES)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)%.out: $(BUILD_DIR)%.cpp.o $(CXXOBJECTS)
	$(CXX) $(LDFLAGS) $< $(OBJECTS) -o $@

