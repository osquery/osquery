all:
	mkdir -p build
	cd build && cmake .. && make $(MAKEFLAGS)

deps:
	/bin/bash ./tools/provision.sh

distclean:
	rm -rf .sources
	rm -rf build
	rm -rf deploy/darwin/build
	rm -rf doxygen/html
	rm -rf doxygen/latex

format:
	clang-format -i osquery/**/*.h
	clang-format -i osquery/**/*.cpp
	clang-format -i osquery/**/**/*.cpp
	clang-format -i osquery/**/**/**/*.cpp
	clang-format -i osquery/**/**/*.mm
	clang-format -i tools/*.cpp

%::
	mkdir -p build
	cd build && cmake .. && make $@
