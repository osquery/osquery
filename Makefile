all: build

.PHONY: build
build:
	mkdir -p build
	cd build && cmake .. && make -j5

clean:
	cd build && make clean

deps:
	pip install -r requirements.txt

distclean:
	rm -rf build

runtests: build
	find build -name "*_tests" -type f -exec '{}' \;


