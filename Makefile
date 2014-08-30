OS=$(shell uname)
BUILD_THREADS=5
ifeq ($(OS),Darwin)
OSQUERYD_PLIST_PATH="/Library/LaunchDaemons/com.facebook.osqueryd.plist"
endif
ROCKSDB_PATH="/tmp/rocksdb-osquery"

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

ifeq ($(OS),Darwin)
clean_install:
	rm -rf /var/osquery
	rm -rf  $(ROCKSDB_PATH)
	rm -f /usr/local/bin/osqueryi
	rm -f /usr/local/bin/osqueryd
	rm -f /var/log/osquery.log
	if [ -f $(OSQUERYD_PLIST_PATH) ]; then launchctl unload $(OSQUERYD_PLIST_PATH); fi;
	rm -f $(OSQUERYD_PLIST_PATH)
endif

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
	rm -rf package/darwin/build
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
	packagesbuild -v package/darwin/osquery.pkgproj
	mkdir -p build/darwin
	mv package/darwin/build/osquery.pkg build/darwin/osquery.pkg
	rm -rf package/darwin/build
endif

pull:
	git submodule init
	git submodule update
	git submodule foreach git pull origin master
	git fetch origin
	git rebase master --stat

runtests: all test
	./build/tools/flag_test --flagfile=tools/osquery.flagfile

tables:
	python tools/gentables.py

t: build test

test:
	find build -name "*_tests" -type f -exec '{}' \;
