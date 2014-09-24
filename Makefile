OS=$(shell uname)
ifeq ($(OS),Darwin)
OSQUERYD_PLIST_PATH="/Library/LaunchDaemons/com.facebook.osqueryd.plist"
endif
ROCKSDB_PATH="/tmp/rocksdb-osquery"

all: build

ammend:
	git add .
	git commit --amend --no-edit

.PHONY: build
build:
	mkdir -p build
	cd build && cmake .. && make $(MAKEFLAGS)

build_shared:
	mkdir -p build/shared
	cd build/shared && cmake -D BUILD_SHARED_LIBS:Boolean=True ../.. && make $(MAKEFLAGS)

fast:
	cd build && cmake .. && make $(MAKEFLAGS)

clean:
	cd build && make clean

.PHONY: docs
docs:
	doxygen Doxyfile

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
	cd build && make install

.PHONY: package
package:
ifeq ($(OS),Darwin)
	packagesbuild -v package/darwin/osquery.pkgproj
	mv package/darwin/build/osquery.pkg build/osquery.pkg
	rm -rf package/darwin/build
else
	cd build && cmake .. && make package $(MAKEFLAGS)
endif

pull:
	git submodule init
	git submodule update
	git submodule foreach git pull origin master
	git fetch origin
	git rebase master --stat

test:
	cd build && cmake .. && make test
