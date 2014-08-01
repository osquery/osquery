all: build

.PHONY: build
build:
	mkdir -p build/osx
	cd build/osx && cmake ../.. && make -j5

clean:
	cd build/osx && make clean

deps:
	pip install -r requirements.txt

distclean:
	rm -rf build

runtests: build
	find build/osx -name "*_tests" -type f -exec '{}' \;


