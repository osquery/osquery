all:
	mkdir -p build
	cd build && cmake .. && make $(MAKEFLAGS)

deps:
	./tools/provision.sh

distclean:
	rm -rf .sources
	rm -rf build
	rm -rf deploy/darwin/build
	rm -rf doxygen/html
	rm -rf doxygen/latex

format:
	find osquery include tools \( -name "*.h" -o -name "*.cpp" -o -name "*.mm" \) -exec clang-format -i {} +

%::
	mkdir -p build
	cd build && cmake .. && make $@
