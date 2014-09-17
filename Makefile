OS=$(shell uname)
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
	cd build && cmake .. && make $(MAKEFLAGS)

build_shared:
	mkdir -p build/shared
	cd build/shared && cmake -D BUILD_SHARED:Boolean=True ../.. && make $(MAKEFLAGS)

fast:
	cd build && cmake .. && make $(MAKEFLAGS)

clean: clean_tables
	cd build && make clean

clean_install:
	rm -rf /var/osquery
	rm -rf  $(ROCKSDB_PATH)
	rm -f /usr/local/bin/osqueryi
	rm -f /usr/local/bin/osqueryd
	rm -rf /var/log/osquery
	rm -f $(OSQUERYD_PLIST_PATH)
ifeq ($(OS),Darwin)
	if [ -f $(OSQUERYD_PLIST_PATH) ]; then           \
		launchctl unload $(OSQUERYD_PLIST_PATH); \
		rm -f $(OSQUERYD_PLIST_PATH);            \
	fi;
endif

clean_tables:
	rm -rf osquery/tables/generated

.PHONY: docs
docs:
	doxygen Doxyfile

os_deps:
ifeq ($(OS),Darwin)
	brew install cmake || brew upgrade cmake
	brew install boost --c++11 --with-python \
		|| brew upgrade boost --c++11 --with-python
	brew install gflags || brew upgrade gflags
	brew install glog || brew ugprade glog
	brew install snappy || brew upgrade snappy
	brew install readline || brew upgrade readline
	brew install thrift || brew upgrade thrift
else
	if [ -f /etc/lsb-release ]; then 		    \
		sudo apt-get install git -y;                     \
		sudo apt-get install build-essential -y;         \
		sudo apt-get install cmake -y;                   \
		sudo apt-get install python-pip -y;              \
		sudo apt-get install python-dev -y;              \
		sudo apt-get install clang-3.4 -y;               \
		sudo apt-get install clang-format-3.4 -y;        \
		sudo apt-get install libboost1.55-all-dev -y;    \
		sudo apt-get install libgflags-dev -y;           \
		sudo apt-get install libgoogle-glog-dev -y;      \
		sudo apt-get install libsnappy-dev -y;           \
		sudo apt-get install libbz2-dev -y;              \
		sudo apt-get install libreadline-dev -y;         \
	elif [ -f /etc/centos-release ]; then         \
		sudo yum install git -y;                         \
		sudo yum install http://dl.atrpms.net/el6-x86_64/atrpms/testing/cmake-2.8.8-4.el6.x86_64.rpm -y; \
	fi;
endif

deps: os_deps
	git submodule init
	git submodule update
	sudo pip install -r requirements.txt

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

tables:
	python tools/gentables.py

test:
	cd build && cmake .. && make test

runtests: build test
