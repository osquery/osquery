cmake_minimum_required(VERSION 2.8.12)

if(NOT DEFINED ENV{CC})
  set(CMAKE_C_COMPILER "clang")
else()
  set(CMAKE_C_COMPILER "$ENV{CC}")
  message("-- Overriding C compiler from clang to $ENV{CC}")
endif()
if(NOT DEFINED ENV{CXX})
  set(CMAKE_CXX_COMPILER "clang++")
else()
  set(CMAKE_CXX_COMPILER "$ENV{CXX}")
  message("-- Overriding CXX compiler from clang++ to $ENV{CXX}")
endif()

add_compile_options(
  -Wall
  -Wextra
  -Wstrict-aliasing
  -Wno-unused-parameter
  -Wno-unused-result
  -Wno-missing-field-initializers
  -Wno-sign-compare
  -Wnon-virtual-dtor
  -Wchar-subscripts
  -Wpointer-arith
  -Woverloaded-virtual
  -Wformat
  -Wformat-security
  -Werror=format-security
  -fstack-protector-all
  -fPIE
)
set(CXX_COMPILE_FLAGS "")

# Use osquery language to set platform/os
if(DEFINED ENV{OSQUERY_PLATFORM})
  set(PLATFORM ENV{OSQUERY_PLATFORM})
else()
  execute_process(
    COMMAND "${CMAKE_SOURCE_DIR}/tools/provision.sh" get_platform
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    OUTPUT_VARIABLE PLATFORM
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
endif()

list(GET PLATFORM 0 OSQUERY_BUILD_PLATFORM)
list(GET PLATFORM 1 OSQUERY_BUILD_DISTRO)
string(REPLACE "." "_" PLATFORM "${PLATFORM}")
string(TOUPPER "${PLATFORM}" PLATFORM)
list(GET PLATFORM 0 OSQUERY_BUILD_PLATFORM_DEFINE)
list(GET PLATFORM 1 OSQUERY_BUILD_DISTRO_DEFINE)

# Set non-C compile flags and whole-loading linker flags.
# osquery needs ALL symbols in the libraries it includes for relaxed ctors
# late-loading modules and SQLite introspection utilities.
if(APPLE)
  set(APPLE_MIN_ABI "10.9")
  set(CXX_COMPILE_FLAGS "${CXX_COMPILE_FLAGS} -std=c++11 -stdlib=libc++")
  set(CXX_COMPILE_FLAGS "${CXX_COMPILE_FLAGS} -mmacosx-version-min=${APPLE_MIN_ABI}")
  set(OS_WHOLELINK_PRE "-Wl,-force_load")
  set(OS_WHOLELINK_POST "")
  # Special compile flags for Objective-C++
  set(OBJCXX_COMPILE_FLAGS
    "-x objective-c++ -fobjc-arc -Wno-c++11-extensions -mmacosx-version-min=${APPLE_MIN_ABI}")
else()
  set(CXX_COMPILE_FLAGS "${CXX_COMPILE_FLAGS} -std=c++11")
  set(OS_WHOLELINK_PRE "-Wl,-whole-archive")
  set(OS_WHOLELINK_POST "-Wl,-no-whole-archive")
  # Set CMAKE variables depending on platform, to know which tables and what
  # component-specific globbing is needed.
  if(${OSQUERY_BUILD_PLATFORM} STREQUAL "freebsd")
    set(FREEBSD TRUE)
    set(LINUX FALSE)
  else()
    set(LINUX TRUE)
    set(FREEBSD FALSE)
  endif()
endif()

# RHEL6 uses a different gcc 4.9 runtime
if(${OSQUERY_BUILD_DISTRO} STREQUAL "rhel6")
  set(GCC_RUNTIME "/opt/rh/devtoolset-3/root/usr/")
  message("-- Setting RHEL6 GCC runtime: ${GCC_RUNTIME}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --gcc-toolchain=${GCC_RUNTIME}")
endif()

# Provisioning installs non-default C++11 runtimes on build hosts.
# List those distros that include a non-system-default runtime.
set(OSQUERY_REQUIRE_RUNTIMES
  "precise"
  "centos6"
  "rhel6"
)

# make debug (environment variable from Makefile)
if(DEFINED ENV{DEBUG})
  set(DEBUG TRUE)
  set(CMAKE_BUILD_TYPE "Debug")
  add_compile_options(-g -O0)
  add_definitions(-DDEBUG)
  message("-- Setting DEBUG build")
elseif(DEFINED ENV{SANITIZE})
  # make sanitize (cannot make debug sanitize)
  add_compile_options(-g -O0 -fno-omit-frame-pointer)
  add_definitions(-DNDEBUG)
  if(DEFINED ENV{SANITIZE_THREAD})
    add_compile_options(-fsanitize=thread)
  else()
    add_compile_options(-fsanitize=leak -fsanitize=address)
  endif()
  set(SANITIZE_BLACKLIST "${CMAKE_SOURCE_DIR}/tools/tests/sanitize_blacklist.txt")
  add_compile_options(-fsanitize-blacklist=${SANITIZE_BLACKLIST})
else()
  set(DEBUG FALSE)
  add_compile_options(-O2)
  add_definitions(-DNDEBUG)
  # Do not enable fortify with clang: http://llvm.org/bugs/show_bug.cgi?id=16821
  #set(C_COMPILE_FLAGS "${C_COMPILE_FLAGS} -D_FORTIFY_SOURCE=2")
endif()

# make analyze (environment variable from Makefile)
if(DEFINED ENV{ANALYZE})
  set(CMAKE_CXX_COMPILER "${CMAKE_SOURCE_DIR}/tools/analysis/clang-analyze.sh")
endif()

# make sdk (tests building SDK-based extensions)
if(DEFINED ENV{SDK})
  set(OSQUERY_BUILD_SDK_ONLY TRUE)
endif()

# make packages will set release to true and blacklist development features,
# development plugins, etc.
if(DEFINED ENV{PACKAGE})
  set(OSQUERY_BUILD_RELEASE TRUE)
else()
  set(OSQUERY_BUILD_RELEASE FALSE)
endif()

# Finished setting compiler/compiler flags.
project(OSQUERY)

# Make sure deps were built before compiling (else show warning).
execute_process(
  COMMAND "${CMAKE_SOURCE_DIR}/tools/provision.sh" check "${CMAKE_BINARY_DIR}"
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  OUTPUT_VARIABLE OSQUERY_DEPS_MESSAGE
  RESULT_VARIABLE OSQUERY_DEPS_CHECK
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(ASCII 27 Esc)
if(OSQUERY_DEPS_CHECK)
  message("-- ${Esc}[31m${OSQUERY_DEPS_MESSAGE}${Esc}[m")
endif()

# Discover build version from an environment variable or from the git checkout.
if(DEFINED ENV{OSQUERY_BUILD_VERSION})
  set(OSQUERY_BUILD_VERSION "$ENV{OSQUERY_BUILD_VERSION}")
else()
  # Generate version from git
  execute_process(
    COMMAND git describe --tags HEAD --always
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    OUTPUT_VARIABLE OSQUERY_BUILD_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
endif()

# Discover the SDK version from an environment variable or the build version.
if(DEFINED ENV{SDK_VERSION})
  set(OSQUERY_BUILD_SDK_VERSION "${ENV{SDK_VERSION}}")
else()
  string(REPLACE "-" ";" OSQUERY_BUILD_SDK_VERSION ${OSQUERY_BUILD_VERSION})
  list(GET OSQUERY_BUILD_SDK_VERSION 0 OSQUERY_BUILD_SDK_VERSION)
endif()

# Set various platform/platform-version/build version/etc defines.
add_definitions(
  -DOSQUERY_BUILD_VERSION=${OSQUERY_BUILD_VERSION}
  -DOSQUERY_BUILD_SDK_VERSION=${OSQUERY_BUILD_SDK_VERSION}
  -DOSQUERY_BUILD_PLATFORM=${OSQUERY_BUILD_PLATFORM}
  -DOSQUERY_BUILD_DISTRO=${OSQUERY_BUILD_DISTRO}
  -D${OSQUERY_BUILD_PLATFORM_DEFINE}
  -D${OSQUERY_BUILD_PLATFORM_DEFINE}_${OSQUERY_BUILD_DISTRO_DEFINE}
)

if(APPLE)
  message("-- Building for OS X")
elseif(OSQUERY_BUILD_PLATFORM STREQUAL "ubuntu")
  set(UBUNTU TRUE)
  message("-- Building for Ubuntu")
elseif(OSQUERY_BUILD_PLATFORM STREQUAL "centos")
  set(CENTOS TRUE)
  message("-- Building for CentOS")
elseif(OSQUERY_BUILD_PLATFORM STREQUAL "rhel")
  set(RHEL TRUE)
  message("-- Building for RHEL")
elseif(OSQUERY_BUILD_PLATFORM STREQUAL "freebsd")
  set(FREEBSD TRUE)
  message("-- Building for FreeBSD")
endif()

# Make sure the generated paths exist
execute_process(COMMAND mkdir -p "${CMAKE_BINARY_DIR}/generated")

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMake" "${CMAKE_MODULE_PATH}")
set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY TRUE)

# We need to link some packages as dynamic/dependent.
set(CMAKE_FIND_LIBRARY_SUFFIXES .dylib .so)
find_package(OpenSSL REQUIRED)
find_package(Crypto REQUIRED)
find_package(BZip2 REQUIRED)
find_package(Dl REQUIRED)
find_package(Readline REQUIRED)

# Most dependent packages/libs we want static.
set(CMAKE_FIND_LIBRARY_SUFFIXES .a .dylib .so)
find_package(CppNetlib 0.11.0 REQUIRED)
find_package(Gflags REQUIRED)
find_package(Glog REQUIRED)
find_package(Gtest REQUIRED)
find_package(RocksDB REQUIRED)
find_package(Snappy REQUIRED)
find_package(Sqlite3 REQUIRED)
find_package(Thrift 0.9.1 REQUIRED)

# Python is used for table spec generation and formating.
find_package(PythonInterp 2 REQUIRED)

enable_testing()

include(CMakeLibs)
include(Packages)
include(Thrift)

include_directories("${GLOG_INCLUDE_DIRS}")
include_directories("${CMAKE_SOURCE_DIR}/include")
include_directories("${CMAKE_SOURCE_DIR}")
include_directories("/usr/local/include")
link_directories("/usr/local/lib")

# Add sysroot overrides for each platform/distro.
if(LINUX)
  include_directories("${CMAKE_SOURCE_DIR}/sysroots/linux")
endif()

add_subdirectory(osquery)
add_subdirectory(tools/tests)

# make docs
find_package(Doxygen)
if(DOXYGEN_FOUND)
  add_custom_target(
    docs
    echo "PROJECT_NUMBER=${OSQUERY_BUILD_VERSION}" |
      cat ${CMAKE_SOURCE_DIR}/Doxyfile - |
      "${DOXYGEN_EXECUTABLE}" -;
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Generating API documentation with Doxygen" VERBATIM
  )
endif(DOXYGEN_FOUND)

# make format-all
add_custom_target(
  format-all
  find osquery include tools \( -name "*.h" -o -name "*.cpp" -o -name "*.mm" \)
    -exec clang-format -i {} +
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  COMMENT "Formatting all osquery code with clang-format" VERBATIM
)

# make format
add_custom_target(
  format
  ${PYTHON_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tools/formatting/git-clang-format.py"
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  COMMENT "Formatting code staged code changes with clang-format" VERBATIM
)

# make sync
add_custom_target(
  sync
  "${CMAKE_SOURCE_DIR}/tools/sync.sh" "${CMAKE_BINARY_DIR}"
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  COMMENT "Generating sdk sync: ${CMAKE_BINARY_DIR}/sync"
  DEPENDS osquery_extensions osquery_amalgamation
)
