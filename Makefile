all: build

.PHONY: build
build:
	mkdir -p build
	cd build && cmake .. && make $(MAKEFLAGS)

.PHONY: docs
docs:
	mkdir -p build
	cd build && cmake .. && make docs $(MAKEFLAGS)

deps:
	/bin/bash ./tools/provision.sh
	git submodule init
	git submodule update

distclean:
	rm -rf build
	rm -rf .sources

format:
	clang-format -i osquery/**/*.h
	clang-format -i osquery/**/*.cpp
	clang-format -i osquery/**/*.mm
	clang-format -i tools/*.cpp

install:
	cd build && cmake .. && make install $(MAKEFLAGS)

.PHONY: package
package:
	cd build && cmake .. && make package $(MAKEFLAGS)

test:
	cd build && cmake .. && make test $(MAKEFLAGS)
