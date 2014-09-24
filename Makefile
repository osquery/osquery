all:
	mkdir -p build
	cd build && cmake .. && make --no-print-directory $(MAKEFLAGS)

deps:
	./tools/provision.sh

distclean:
	rm -rf .sources build deploy/darwin/build doxygen/html doxygen/latex

%::
	mkdir -p build
	cd build && cmake .. && make --no-print-directory $@
