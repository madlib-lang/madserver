# Inputs
CXX ?= clang++
AR ?= llvm-ar


INCLUDEDIR := include
BUILDDIR := build
SRCDIR := src
OBJS :=\
  $(BUILDDIR)/server.o

MADLIB_RUNTIME_HEADERS_PATH := "$(shell madlib config runtime-headers-path)"
MADLIB_RUNTIME_LIB_HEADERS_PATH := "$(shell madlib config runtime-lib-headers-path)"

build: prepare build/libmadserver.a print_done

prepare:
	@mkdir -p build

print_done:
	@echo "build done.\noutput: build/libmadserver.a"

$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp
	$(CXX) -g -I$(INCLUDEDIR) -I$(MADLIB_RUNTIME_HEADERS_PATH) -I$(MADLIB_RUNTIME_LIB_HEADERS_PATH) -std=c++17 -O1 -fPIC $(CXXFLAGS) -c $< -o $@

build/libmadserver.a: $(OBJS)
	$(AR) rc $@ $^
