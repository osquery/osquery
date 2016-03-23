cmake_minimum_required(VERSION 2.8.12)
string(ASCII 27 ESC)
macro(WARNING_LOG MESSAGE)
  message("-- ${ESC}[31m${MESSAGE}${ESC}[m")
endmacro(WARNING_LOG)

macro(LOG MESSAGE)
  message("-- ${MESSAGE}")
endmacro(LOG)

# If no explicit compiler override and clang++ exists, prefer clang.
find_file(CLANGXX_EXISTS "clang++")
if(DEFINED ENV{CC})
  set(CMAKE_C_COMPILER "$ENV{CC}")
  LOG("Overriding C compiler from clang to $ENV{CC}")
elseif(CLANGXX_EXISTS)
  set(CMAKE_C_COMPILER "clang")
endif()
if(DEFINED ENV{CXX})
  set(CMAKE_CXX_COMPILER "$ENV{CXX}")
  LOG("Overriding CXX compiler from clang++ to $ENV{CXX}")
elseif(CLANGXX_EXISTS)
  set(CMAKE_CXX_COMPILER "clang++")
endif()

if(WIN32)
  # TODO(WIN64): Put customized compiler options here
else()
  add_compile_options(
    -Wstrict-aliasing
    -Wno-missing-field-initializers
    -Wno-unused-local-typedef
    -Wno-unknown-warning-option
    -Wnon-virtual-dtor
    -Wchar-subscripts
    -Wpointer-arith
    -Woverloaded-virtual
    -Wformat
    -Wformat-security
    -Werror=format-security
    -Wabi-tag
    -fstack-protector-all
    -fPIE
    -fpie
    -fPIC
    -fpic
    -pipe
    -fdata-sections
    -ffunction-sections
  )
endif()

# osquery additional compiler flags added by CMake.
set(C_COMPILE_FLAGS "")
set(CXX_COMPILE_FLAGS "")

# Use osquery language to set platform/os
if(DEFINED ENV{OSQUERY_PLATFORM})
  set(PLATFORM "$ENV{OSQUERY_PLATFORM}")
else()
  execute_process(
    COMMAND python "${CMAKE_SOURCE_DIR}/tools/get_platform.py"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    OUTPUT_VARIABLE PLATFORM
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
endif()

if(PLATFORM STREQUAL "")
  WARNING_LOG("Unable to detect osquery platform: ./tools/provision.sh failed")
  message(FATAL_ERROR "Cannot proceed without knowing the build platform")
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
  if(DEFINED ENV{OSX_VERSION_MIN})
    set(OSX_VERSION_MIN "$ENV{OSX_VERSION_MIN}")
  else()
    set(OSX_VERSION_MIN "${OSQUERY_BUILD_DISTRO}")
  endif()
  add_compile_options(
    -mmacosx-version-min=${OSX_VERSION_MIN}
  )

  set(CXX_COMPILE_FLAGS "${CXX_COMPILE_FLAGS} -std=c++11 -stdlib=libc++")
  set(OS_WHOLELINK_PRE "-Wl,-force_load")
  set(OS_WHOLELINK_POST "")
  # Special compile flags for Objective-C++
  set(OBJCXX_COMPILE_FLAGS
    "-x objective-c++ -fobjc-arc -Wno-c++11-extensions")
elseif(WIN32)
  # Windows
  # C++11 features should be on by default in 2012 and beyond.
else()
  set(CXX_COMPILE_FLAGS "${CXX_COMPILE_FLAGS} -std=c++11")
  set(OS_WHOLELINK_PRE "-Wl,-whole-archive")
  set(OS_WHOLELINK_POST "-Wl,-no-whole-archive")
  # Set CMAKE variables depending on platform, to know which tables and what
  # component-specific globbing is needed.
  if(${OSQUERY_BUILD_PLATFORM} STREQUAL "freebsd")
    set(FREEBSD TRUE)
    set(LINUX FALSE)
    set(ENV{SKIP_BENCHMARKS}, "TRUE")
  else()
    set(LINUX TRUE)
    set(FREEBSD FALSE)
  endif()
endif()

# RHEL6 uses a different gcc 4.9 runtime
if(${OSQUERY_BUILD_DISTRO} STREQUAL "rhel6")
  set(GCC_RUNTIME "/opt/rh/devtoolset-3/root/usr/")
  WARNING_LOG("Setting RHEL6 GCC runtime: ${GCC_RUNTIME}")
  set(CMAKE_C_COMPILER "${CMAKE_C_COMPILER}" "--gcc-toolchain=${GCC_RUNTIME}")
  set(CMAKE_CXX_COMPILER "${CMAKE_CXX_COMPILER}" "--gcc-toolchain=${GCC_RUNTIME}")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --gcc-toolchain=${GCC_RUNTIME}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --gcc-toolchain=${GCC_RUNTIME}")
  set(C_COMPILE_FLAGS "${C_COMPILE_FLAGS} --gcc-toolchain=${GCC_RUNTIME}")
  set(CXX_COMPILE_FLAGS "${CXX_COMPILE_FLAGS} --gcc-toolchain=${GCC_RUNTIME}")
endif()

# Help Debian Wheezy find BZip2
if(${OSQUERY_BUILD_DISTRO} STREQUAL "wheezy")
  set (CMAKE_PREFIX_PATH "/usr/lib/x86_64-linux-gnu")
endif()

# Provisioning installs non-default C++11 runtimes on build hosts.
# List those distros that include a non-system-default runtime.
set(OSQUERY_REQUIRE_RUNTIMES
  "lucid"
  "precise"
  "centos6"
  "rhel6"
  "oracle6"
  "wheezy"
)

# make debug (environment variable from Makefile)
if(DEFINED ENV{DEBUG})
  set(DEBUG TRUE)
  set(CMAKE_BUILD_TYPE "Debug")
  if(WIN32)
    # TODO(WIN64): any other compile options to add?
    add_compile_options(
      /Zi
      /Od   
    )
  else()
    add_compile_options(
      -g
      -O0
      -fstandalone-debug
    )
  endif()
  add_definitions(-DDEBUG)
  WARNING_LOG("Setting DEBUG build")
elseif(DEFINED ENV{SANITIZE})
  # TODO(WIN64): need to deal with these compile options...
  # make sanitize (cannot make debug sanitize)
  add_compile_options(
    -g
    -O1
    -fstandalone-debug
    -fno-omit-frame-pointer
    -fno-optimize-sibling-calls
  )
  add_definitions(-DNDEBUG)
  if(DEFINED ENV{SANITIZE_THREAD})
    add_compile_options(-fsanitize=thread)
  else()
    add_compile_options(-fsanitize=address)
    if (NOT APPLE)
      add_compile_options(-fsanitize=leak)
    endif()
  endif()
  set(SANITIZE_BLACKLIST "${CMAKE_SOURCE_DIR}/tools/tests/sanitize_blacklist.txt")
  add_definitions(-fsanitize-blacklist=${SANITIZE_BLACKLIST})
else()
  set(DEBUG FALSE)
  # TODO(WIN64): more options to change for windows
  if(WIN32)
    add_compile_options(/Ot)
  else()
    add_compile_options(-Os)
  endif()
  add_definitions(-DNDEBUG)
  # Do not enable fortify with clang: http://llvm.org/bugs/show_bug.cgi?id=16821
  #set(C_COMPILE_FLAGS "${C_COMPILE_FLAGS} -D_FORTIFY_SOURCE=2")
endif()
# Generate a compile_commands.json for static analyzer input.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT DEFINED ENV{OPTIMIZED})
  # TODO(WIN64): I think by default no-avx is implied if not added as /arch:AVX
  if(WIN32)
    add_compile_options(/favor:AMD64)
  else()
    add_compile_options(-march=x86-64 -mno-avx)
  endif()
endif()

# make analyze (environment variable from Makefile)
if(DEFINED ENV{ANALYZE})
  # TODO(WIN64): ignore the analyzer option for now
  if(WIN32)
    message(FATAL_ERROR "Cannot analyze on Win64 right now." )
  else()
    set(CMAKE_CXX_COMPILER "${CMAKE_SOURCE_DIR}/tools/analysis/clang-analyze.sh")
  endif()
endif()

# make sdk (tests building SDK-based extensions)
if(DEFINED ENV{SDK})
  set(OSQUERY_BUILD_SDK_ONLY TRUE)
else()
  set(OSQUERY_BUILD_SDK_ONLY FALSE)
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
set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY TRUE)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMake" "${CMAKE_MODULE_PATH}")
include(CMakeLibs)

if(NOT IS_DIRECTORY ${CMAKE_SOURCE_DIR}/third-party/sqlite3)
  WARNING_LOG("Cannot find git submodule third-party/sqlite3 directory")
  WARNING_LOG("Please run: make deps or git submodule update --init")
  message(FATAL_ERROR "No sqlite3 directory")
endif()

# Make sure deps were built before compiling (else show warning).
execute_process(
  COMMAND "${CMAKE_SOURCE_DIR}/tools/provision.sh" check "${CMAKE_BINARY_DIR}"
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  OUTPUT_VARIABLE OSQUERY_DEPS_MESSAGE
  RESULT_VARIABLE OSQUERY_DEPS_CHECK
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(OSQUERY_DEPS_CHECK)
  WARNING_LOG("${OSQUERY_DEPS_MESSAGE}")
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
if(OSQUERY_BUILD_VERSION STREQUAL "")
  WARNING_LOG("Unable to detect osquery version: 'git describe' failed")
  WARNING_LOG("Setting the version to: 1.0.0-unknown (beware!)")
  set(OSQUERY_BUILD_VERSION "1.0.0-unknown")
endif()
if(DEFINED ENV{SDK_VERSION})
  set(OSQUERY_BUILD_SDK_VERSION "${ENV{SDK_VERSION}}")
else()
  string(REPLACE "-" ";" OSQUERY_BUILD_SDK_VERSION ${OSQUERY_BUILD_VERSION})
  list(GET OSQUERY_BUILD_SDK_VERSION 0 OSQUERY_BUILD_SDK_VERSION)
endif()

# Set various platform/platform-version/build version/etc defines.
add_definitions(
  -DOSQUERY_BUILD_SDK_VERSION=${OSQUERY_BUILD_SDK_VERSION}
  -DOSQUERY_BUILD_PLATFORM=${OSQUERY_BUILD_PLATFORM}
  -DOSQUERY_BUILD_DISTRO=${OSQUERY_BUILD_DISTRO}
  -D${OSQUERY_BUILD_PLATFORM_DEFINE}
  -D${OSQUERY_BUILD_PLATFORM_DEFINE}_${OSQUERY_BUILD_DISTRO_DEFINE}
  -DSTRIP_FLAG_HELP=1
  -DBOOST_NETWORK_ENABLE_HTTPS
  -DBOOST_NO_CXX11_VARIADIC_TEMPLATES
)

if(DEFINED ENV{SQLITE_DEBUG})
  add_definitions(
    -DSQLITE_DEBUG=1
    -DSQLITE_ENABLE_WHERETRACE=1
  )
endif()

if(APPLE)
  LOG_PLATFORM("OS X")
elseif(OSQUERY_BUILD_PLATFORM STREQUAL "debian")
  set(DEBIAN_BASED TRUE)
  set(DEBIAN TRUE)
  LOG_PLATFORM("Debian")
elseif(OSQUERY_BUILD_PLATFORM STREQUAL "ubuntu")
  set(DEBIAN_BASED TRUE)
  set(UBUNTU TRUE)
  LOG_PLATFORM("Ubuntu")
elseif(OSQUERY_BUILD_PLATFORM STREQUAL "centos")
  set(REDHAT_BASED TRUE)
  set(CENTOS TRUE)
  LOG_PLATFORM("CentOS")
elseif(OSQUERY_BUILD_PLATFORM STREQUAL "rhel")
  set(REDHAT_BASED TRUE)
  set(RHEL TRUE)
  LOG_PLATFORM("RHEL")
elseif(OSQUERY_BUILD_PLATFORM STREQUAL "amazon")
  set(REDHAT_BASED TRUE)
  set(AMAZON TRUE)
  LOG_PLATFORM("Amazon Linux")
elseif(OSQUERY_BUILD_PLATFORM STREQUAL "oracle")
  set(REDHAT_BASED TRUE)
  set(ORACLE TRUE)
  LOG_PLATFORM("Oracle Linux")
elseif(OSQUERY_BUILD_PLATFORM STREQUAL "freebsd")
  set(FREEBSD TRUE)
  LOG_PLATFORM("FreeBSD")
elseif(OSQUERY_BUILD_PLATFORM STREQUAL "windows")
  set(WINDOWS TRUE)
  LOG_PLATFORM("Windows")
endif()

if("${OSQUERY_BUILD_DISTRO}" MATCHES "^(centos|rhel|oracle)7$")
  # Useful for libudev version detection.
  set(SYSTEMD TRUE)
endif()

if(REDHAT_BASED)
  add_definitions(-DREDHAT_BASED=1)
elseif(DEBIAN_BASED)
  add_definitions(-DDEBIAN_BASED=1)
endif()

if(WIN32)
  set(MKDIR_OPTS "")
  
  # Win64 does not have a kernel build component-specific
  set(OSQUERY_BUILD_SDK_ONLY TRUE)
  
  # Win64 specific BZIP2 variables
  set(BZIP2_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/third-party/bzip2-1.0.6")
  set(BZIP2_LIBRARIES "${CMAKE_SOURCE_DIR}/third-party/bzip2-1.0.6/libbz2.lib")
  
  # Win64 specific OpenSSL variables
  set(OPENSSL_ROOT_DIR "${CMAKE_SOURCE_DIR}/third-party/openssl/out32dll")
  set(OPENSSL_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/third-party/openssl/inc32")
  set(OPENSSL_CRYPTO_LIBRARY "${CMAKE_SOURCE_DIR}/third-party/openssl/out32dll/libeay32.lib")
  set(OPENSSL_SSL_LIBRARY "${CMAKE_SOURCE_DIR}/third-party/openssl/out32dll/ssleay32.lib")
  set(OPENSSL_LIBRARIES ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
  set(OPENSSL_USE_STATIC_LIBS TRUE)
  
  # Win64 specific Thrift
  set(THRIFT_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/third-party/thrift/lib/cpp/src")
  set(THRIFT_LIBRARY "${CMAKE_SOURCE_DIR}/third-party/thrift/cmake-build/lib/Release/thriftmd.lib")
  set(THRIFT_COMPILER "${CMAKE_SOURCE_DIR}/third-party/thrift-compiler/thrift-0.9.3.exe")
  
  # Win64 specific rocksdb
  set(ROCKSDB_STATIC_LIBRARY "${CMAKE_SOURCE_DIR}/third-party/rocksdb/build/Release/rocksdb.lib")
  set(ROCKSDB_SNAPPY_LIBRARY "${CMAKE_SOURCE_DIR}/third-party/snappy-windows-1.1.1.8/native/snappy64.lib")
  
  # Win64 specific doxygen
  set(DOXYGEN_EXECUTABLE "${CMAKE_SOURCE_DIR}/third-party/doxygen-1.8.11.windows.x64.bin/doxygen.exe")

  # Win64 specific boost
  set(boost_filesystem_library "${CMAKE_SOURCE_DIR}/third-party/boost_1_59_0/lib64-msvc-14.0/boost_filesystem-vc140-mt-1_59.lib")
  set(boost_system_library "${CMAKE_SOURCE_DIR}/third-party/boost_1_59_0/lib64-msvc-14.0/boost_system-vc140-mt-1_59.lib")
  set(boost_regex_library "${CMAKE_SOURCE_DIR}/third-party/boost_1_59_0/lib64-msvc-14.0/boost_regex-vc140-mt-1_59.lib")

  # Win64 specific gflags
  set(gflags_library "${CMAKE_SOURCE_DIR}/third-party/gflags/cmake-build/lib/Release/gflags_static.lib")
  
  # Win64 specific glog
  set(glog_library "${CMAKE_SOURCE_DIR}/third-party/glog-w64/build/Release/glog.lib")
  
  # Win64 specific yara
  set(yara_library "${CMAKE_SOURCE_DIR}/third-party/yara-3.4.0/windows/libyara/Release/libyara64.lib")
else()
  set(MKDIR_OPTS "-p")
endif()

# Make sure the generated paths exist 
execute_process(COMMAND mkdir ${MKDIR_OPTS} "${CMAKE_BINARY_DIR}/generated")

# We need to link some packages as dynamic/dependent.
set(CMAKE_FIND_LIBRARY_SUFFIXES .dll .dylib .so .a)

find_package(BZip2 REQUIRED)

if(NOT WIN32)
	find_package(Dl REQUIRED)
endif()

find_package(Readline REQUIRED)

# Apple has deprecated OpenSSL, static link with brew bottled libressl
if(APPLE)
  if(DEFINED ENV{BUILD_USE_LIBRESSL} OR ${OSQUERY_BUILD_DISTRO} STREQUAL "10.11")
    if(NOT DEFINED ENV{BUILD_LINK_SHARED})
      set(CMAKE_FIND_LIBRARY_SUFFIXES .a .dylib .so)
    endif()
    execute_process(COMMAND brew --prefix OUTPUT_VARIABLE BREW_PREFIX OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(OPENSSL_ROOT_DIR "${BREW_PREFIX}/opt/libressl")
  else()
    # Some installs may find the optional brew /usr/local/lib/ as the root.
    set(OPENSSL_ROOT_DIR "/usr")
  endif()
endif()

find_package(OpenSSL REQUIRED)
include_directories("${OPENSSL_INCLUDE_DIR}")

# Make sure the OpenSSL/ssl library has a TLS client method.
# Prefer the highest version of TLS, but accept 1.2, 1.1, or 1.0.
include(CheckLibraryExists)
set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_LIBRARIES})
CHECK_LIBRARY_EXISTS(${OPENSSL_SSL_LIBRARY} "SSLv3_client_method" "" OPENSSL_SSL3)
CHECK_LIBRARY_EXISTS(${OPENSSL_SSL_LIBRARY} "TLSv1_2_client_method" "" OPENSSL_TLSV12)
CHECK_LIBRARY_EXISTS(${OPENSSL_SSL_LIBRARY} "TLSv1_1_client_method" "" OPENSSL_TLSV11)
CHECK_LIBRARY_EXISTS(${OPENSSL_SSL_LIBRARY} "TLSv1_client_method" "" OPENSSL_TLSV10)

# Add a define based on the highest TLS version found. Fatal if no TLS client.
if(OPENSSL_TLSV12)
  add_definitions(-DHAS_SSL_TXT_TLSV1_2)
elseif(OPENSSL_TLSV11)
  add_definitions(-DHAS_SSL_TXT_TLSV1_1)
elseif(OPENSSL_TLSV10)
  add_definitions(-DHAS_SSL_TXT_TLSV1)
else()
  message(FATAL_ERROR "Cannot find any TLS client methods")
endif()
if(NOT OPENSSL_SSL3)
  add_definitions(-DNO_SSL_TXT_SSLV3)
endif()

# Most dependent packages/libs we want static.
if(NOT DEFINED ENV{BUILD_LINK_SHARED})
  set(CMAKE_FIND_LIBRARY_SUFFIXES .a .dylib .so)
endif()

if(DEFINED ENV{BOOST_ROOT})
  set(BOOST_ROOT "$ENV{BOOST_ROOT}")
  include_directories("${BOOST_ROOT}")
endif()

find_package(Gtest REQUIRED)
find_package(Thrift 0.9.3 REQUIRED)

# If using the RocksDB LITE version our code must also define ROCKSDB_LITE=1
if(NOT DEFINED ENV{SKIP_ROCKSDB})
  set(ROCKSDB TRUE)
  find_package(RocksDB REQUIRED)
endif()

# Python is used for table spec generation and formating.
if(PYTHON_VERSION_MAJOR STREQUAL "2" AND PYTHON_VERSION_MINOR STREQUAL "4")
  WARNING_LOG("Found python 2.4, overriding to /usr/bin/python2.6")
  set(PYTHON_EXECUTABLE "/usr/bin/python2.6")
endif()

enable_testing()

include(Packages)
include(Thrift)

include_directories("${CMAKE_SOURCE_DIR}/third-party/sqlite3")
include_directories("${CMAKE_SOURCE_DIR}/include")
include_directories("${CMAKE_SOURCE_DIR}")

# TODO(WIN64): Unix specific things
if(WIN32)
  # We might have to provide include directories by hand...
  include_directories("${THRIFT_INCLUDE_DIR}")
  include_directories("${CMAKE_SOURCE_DIR}/third-party/boost_1_59_0")
  include_directories("${CMAKE_SOURCE_DIR}/third-party/glog-w64/src/windows")
  include_directories("${CMAKE_SOURCE_DIR}/third-party/gflags/cmake-build/include")
  
  # TODO(WIN64): For the future, we probably need to add link_directories...
else()
  include_directories("/usr/local/include")
  link_directories("/usr/local/lib")
endif()

# Add custom homebrew paths
if(APPLE)
  execute_process(COMMAND brew --prefix OUTPUT_VARIABLE BREW_PREFIX OUTPUT_STRIP_TRAILING_WHITESPACE)
  include_directories("${BREW_PREFIX}/include")
  link_directories("${BREW_PREFIX}/lib")
endif()

# Add sysroot overrides for each platform/distro.
if(APPLE)
  include_directories("${CMAKE_SOURCE_DIR}/third-party/sysroots/darwin")
elseif(LINUX)
  include_directories("${CMAKE_SOURCE_DIR}/third-party/sysroots/linux")
endif()

add_subdirectory("${CMAKE_SOURCE_DIR}/third-party/sqlite3")
add_subdirectory(osquery)
add_subdirectory(tools/tests)

# Include the kernel building targets/macros
if(NOT ${OSQUERY_BUILD_SDK_ONLY})
  add_subdirectory(kernel)
endif()

# make docs
find_package(Doxygen)
if(DOXYGEN_FOUND)
  add_custom_target(
    docs
    COMMAND "${CMAKE_SOURCE_DIR}/tools/codegen/genapi.py" "${CMAKE_SOURCE_DIR}"
      "--output" "--directory" "${CMAKE_SOURCE_DIR}/build/docs"
    COMMAND echo "PROJECT_NUMBER=${OSQUERY_BUILD_VERSION}" |
      cat ${CMAKE_SOURCE_DIR}/Doxyfile - |
      "${DOXYGEN_EXECUTABLE}" -;
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Generating API documentation with Doxygen" VERBATIM
  )
endif(DOXYGEN_FOUND)

# TODO(WIN64): NEed to windows-ify this
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

# TODO(WIN64): need to deal with sync.sh bash script...
# make sync
add_custom_target(
  sync
  "${CMAKE_SOURCE_DIR}/tools/sync.sh" "${CMAKE_BINARY_DIR}"
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  COMMENT "Generating sdk sync: ${CMAKE_BINARY_DIR}/sync"
  DEPENDS osquery_extensions osquery_amalgamation
)
