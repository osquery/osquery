all: build

.PHONY: build
build:
	mkdir -p osquery/tables/generated
	python tools/gentable.py osquery/tables/specs/generated_example.table
	python tools/gentable.py osquery/tables/specs/etc_hosts.table
	python tools/gentable.py osquery/tables/specs/kextstat.table
	python tools/gentable.py osquery/tables/specs/processes.table
	mkdir -p build
	cd build && cmake .. && make -j5

clean:
	cd build && make clean
	rm -rf osquery/tables/generated

deps:
	pip install -r requirements.txt
	brew install cmake
	brew install boost --c++11 --with-python
	brew install gflags
	brew install glog
	brew install snappy
	brew install readline
	git submodule init
	git submodule update

distclean:
	rm -rf build
	rm -rf osquery/tables/generated

runtests: build
	find build -name "*_tests" -type f -exec '{}' \;

update:
	git submodule foreach git pull origin master
