.DEFAULT_GOAL := help
THREAD_COUNT=$(shell echo "$(shell nproc --all)*.8/1" | bc)

#help:	@ List available tasks on this project
help:
	@grep -E '[a-zA-Z\.\-]+:.*?@ .*$$' $(MAKEFILE_LIST)| tr -d '#'  | awk 'BEGIN {FS = ":.*?@ "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

#test.all: @ Run all tests
test.all:
	cd build; cmake --build . --target test

#test.all.detail: @ Run all test with high detail output
test.all.detail:
	cd build; CTEST_OUTPUT_ON_FAILURE=1 cmake --build . --target test

#test.specific: @ Run specific test, specified like TEST=networking
test.specific: 
	cd build; ctest -R ${TEST} -V

#test.specific.filtered: @ Run specific test, specified like TEST=networking with additional filter specified like FILTER="sharedMemory.*"
test.specific.filtered: 
	cd build; GTEST_FILTER=${FILTER} ctest -R ${TEST} -V

#check: @ Run cppcheck 
check:
	cd build; cmake --build . --target cppcheck

#setup.all: @ Perform all setup actions required before building osquery
setup.all: setup.host setup.cmake

#setup.host: @ Setup this host, typically a container. In a Devcontainer this was done for you already
setup.host:
	.devcontainer/host_setup.sh

#setup.cmake: @ Run cmake to prepare for build. In a Devcontainer this was done for you already
setup.cmake:
	mkdir -p build
	cd build; cmake -DOSQUERY_BUILD_TESTS=ON -DOSQUERY_TOOLCHAIN_SYSROOT=/usr/local/osquery-toolchain ..

#build: @ Build osquery binary
build:
	cd build; cmake --build . -j${THREAD_COUNT}

.PHONY: help test.all test.all.detail setup cmake build
