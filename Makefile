all: build

.PHONY: build
build:
	mkdir -p osquery/tables/generated
	python tools/gentable.py osquery/tables/specs/generated_example.table
	python tools/gentable.py osquery/tables/specs/etc_hosts.table
	mkdir -p build
	cd build && cmake .. && make -j5

clean:
	cd build && make clean

deps:
	pip install -r requirements.txt

distclean:
	rm -rf build
	rm -rf osquery/tables/generated

runtests: build
	find build -name "*_tests" -type f -exec '{}' \;


