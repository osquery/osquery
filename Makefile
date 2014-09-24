all: build

.PHONY: build
build: cmake
	cd build && make $(MAKEFLAGS)

.PHONY: cmake
cmake:
	mkdir -p build
	cd build && cmake ..

deps:
	/bin/bash ./tools/provision.sh

distclean:
	rm -rf build
	rm -rf .sources
	rm -rf doxygen/html
	rm -rf doxygen/latex
	rm -rf packages/darwin/build

.PHONY: docs
docs: cmake
	cd build && make docs $(MAKEFLAGS)

format:
	clang-format -i osquery/**/*.h
	clang-format -i osquery/**/*.cpp
	clang-format -i osquery/**/**/*.cpp
	clang-format -i osquery/**/**/**/*.cpp
	clang-format -i osquery/**/**/*.mm
	clang-format -i tools/*.cpp

install: cmake
	cd build && make install $(MAKEFLAGS)

.PHONY: package
package: cmake
	cd build && make package $(MAKEFLAGS)

test: build
	cd build && make test $(MAKEFLAGS)
