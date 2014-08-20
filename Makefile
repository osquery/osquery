OS=$(shell uname)
BUILD_THREADS=5

all: tables build

ammend:
	git add .
	git commit --amend --no-edit

.PHONY: build
build:
	mkdir -p build
	cd build && cmake .. && make -j$(BUILD_THREADS)

clean: clean_tables
	cd build && make clean

clean_tables:
	rm -rf osquery/tables/generated

deps:
	git submodule init
	git submodule update
	pip install -r requirements.txt
ifeq ($(OS),Darwin)
	brew install cmake
	brew install boost --c++11 --with-python
	brew install gflags
	brew install glog
	brew install snappy
	brew install readline
endif

distclean: clean_tables
ifeq ($(OS),Darwin)
	rm -rf package/osx/build
endif
	rm -rf build

format:
	clang-format -i osquery/**/*.h
	clang-format -i osquery/**/*.cpp
	clang-format -i osquery/**/*.mm
	clang-format -i tools/*.cpp

.PHONY: package
package: all
	git submodule init
	git submodule update
ifeq ($(OS),Darwin)
	packagesbuild -v package/osx/osquery.pkgproj
	mkdir -p build/osx
	mv package/osx/build/osquery.pkg build/osx/osquery.pkg
	rm -rf package/osx/build
endif

pull:
	git submodule init
	git submodule update
	git submodule foreach git pull origin master
	git fetch origin
	git rebase master --stat

runtests: all
	./build/tools/flag_test --flagfile=tools/osquery.flagfile
	find build -name "*_tests" -type f -exec '{}' \;

tables:
	python tools/gentables.py

test:
	find build -name "*_tests" -type f -exec '{}' \;
