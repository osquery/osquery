#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

cmake_minimum_required(VERSION 2.8.12)
string(ASCII 27 ESC)
macro(WARNING_LOG MESSAGE)
  message("-- ${ESC}[31m${MESSAGE}${ESC}[m")
endmacro(WARNING_LOG)

macro(LOG MESSAGE)
  message("-- ${MESSAGE}")
endmacro(LOG)

# Set expected directory for within-build dependencies
if(DEFINED ENV{OSQUERY_DEPS})
  set(BUILD_DEPS "$ENV{OSQUERY_DEPS}")
else()
  set(BUILD_DEPS "/usr/local/osquery")
endif()

if(WIN32)
  set(WINDOWS_DEP_DIR "$ENV{ChocolateyInstall}/lib")
  string(REGEX REPLACE "\\\\" "/" WINDOWS_DEP_DIR ${WINDOWS_DEP_DIR})
  list(APPEND WINDOWS_DEP_LIST ${WINDOWS_DEP_DIR})

  list(APPEND CMAKE_PROGRAM_PATH "${WINDOWS_DEP_DIR}/*/tools")
endif()

# If no explicit compiler override and clang++ exists, prefer clang.
find_program(CLANGXX_EXECUTABLE "clang++" ENV PATH)
if(DEFINED ENV{CC})
  set(CMAKE_C_COMPILER "$ENV{CC}")
  LOG("Overriding C compiler from clang to $ENV{CC}")
elseif(CLANGXX_EXECUTABLE)
  set(CMAKE_C_COMPILER "clang")
endif()
if(DEFINED ENV{CXX})
  set(CMAKE_CXX_COMPILER "$ENV{CXX}")
  LOG("Overriding CXX compiler from clang++ to $ENV{CXX}")
elseif(CLANGXX_EXECUTABLE)
  set(CMAKE_CXX_COMPILER "clang++")
endif()

if(NOT DEFINED ENV{SKIP_CCACHE})
  find_program(CCACHE_EXECUTABLE ccache ENV PATH)
  if(CCACHE_EXECUTABLE)
    if(NOT DEFINED CCACHE_FOUND_LOG)
      set(CCACHE_FOUND_LOG TRUE CACHE BOOL "Write log line for ccache.")
      LOG("Found ccache ${CCACHE_EXECUTABLE}")
      LOG("Using ccache to speed up compilation")
    endif()
    set(ENV{CCACHE_CPP2} "yes")
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_EXECUTABLE}")
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK "${CCACHE_EXECUTABLE}")
  endif()
endif()

# osquery additional compiler flags added by CMake.
set(C_COMPILE_FLAGS "")
set(CXX_COMPILE_FLAGS "")

find_program(PYTHON_EXECUTABLE "python" ${BUILD_DEPS} ENV PATH)
find_program(THRIFT_COMPILER "thrift" ${BUILD_DEPS} ENV PATH)

# Use osquery language to set platform/os
if(DEFINED ENV{OSQUERY_PLATFORM})
  set(PLATFORM "$ENV{OSQUERY_PLATFORM}")
else()
  execute_process(
    COMMAND "${PYTHON_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/tools/get_platform.py"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    OUTPUT_VARIABLE PLATFORM
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
endif()

if(PLATFORM STREQUAL "")
  WARNING_LOG("Unable to detect osquery platform: ./tools/get_platform.py failed")
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

  set(CXX_COMPILE_FLAGS "${CXX_COMPILE_FLAGS} -std=c++14 -stdlib=libc++")
  set(OS_WHOLELINK_PRE "-Wl,-force_load")
  set(OS_WHOLELINK_POST "")
  # Special compile flags for Objective-C++
  set(OBJCXX_COMPILE_FLAGS
    "-x objective-c++ -fobjc-arc -Wno-c++11-extensions")
  set(POSIX TRUE)
elseif(WIN32)
  # Windows
  # C++11 features should be on by default in 2012 and beyond.
  set(OS_WHOLELINK_PRE "-WHOLEARCHIVE:")
  set(OS_WHOLELINK_POST "")
  set(WINDOWS TRUE)
else()
  set(OS_WHOLELINK_PRE "-Wl,-whole-archive")
  set(OS_WHOLELINK_POST "-Wl,-no-whole-archive")
  # Set CMAKE variables depending on platform, to know which tables and what
  # component-specific globbing is needed.
  if(${OSQUERY_BUILD_PLATFORM} STREQUAL "freebsd")
    set(FREEBSD TRUE)
    include_directories("/usr/local/include")
    include_directories("/usr/include")
    set(CXX_COMPILE_FLAGS "${CXX_COMPILE_FLAGS} -std=c++14 -stdlib=libc++")
  else()
    set(LINUX TRUE)
    set(CXX_COMPILE_FLAGS "${CXX_COMPILE_FLAGS} -std=c++14 -stdlib=libstdc++")
  endif()
  set(POSIX TRUE)
endif()

if(POSIX)
  add_compile_options(
    -Qunused-arguments
    -Wstrict-aliasing
    -Wno-missing-field-initializers
    -Wno-unused-local-typedef
    -Wno-deprecated-register
    -Wno-unknown-warning-option
    -Wnon-virtual-dtor
    -Wchar-subscripts
    -Wpointer-arith
    -Woverloaded-virtual
    -Wformat
    -Wformat-security
    -Werror=format-security
    -Wabi-tag
    -fpermissive
    -fstack-protector-all
    -pipe
    -fdata-sections
    -ffunction-sections
  )
  if(NOT FREEBSD)
    add_compile_options(
      -Werror=shadow
      -fvisibility=hidden
      -fvisibility-inlines-hidden
    )
  endif()
elseif(WINDOWS)
  add_compile_options(
    /EHsc
    /W3
    /guard:cf
  )
  add_definitions(-DBOOST_ALL_NO_LIB)
endif()

set(TEST_ARGS "")
if(LINUX AND CMAKE_CXX_COMPILER MATCHES "clang")
  # Use the LLVM versions of ar and ranlib to support LTO builds
  find_program(LLVMRANLIB_EXECUTABLE "llvm-ranlib" ENV PATH)
  find_program(LLVMAR_EXECUTABLE "llvm-ar" ENV PATH)
  set(CMAKE_AR "${LLVMAR_EXECUTABLE}")
  set(CMAKE_RANLIB "${LLVMRANLIB_EXECUTABLE}")
  set(CMAKE_C_ARCHIVE_CREATE "${LLVMAR_EXECUTABLE} qc <TARGET> <LINK_FLAGS> <OBJECTS>")
  set(CMAKE_CXX_ARCHIVE_CREATE "${LLVMAR_EXECUTABLE} qc <TARGET> <LINK_FLAGS> <OBJECTS>")
  set(CMAKE_C_ARCHIVE_FINISH "${LLVMRANLIB_EXECUTABLE} <TARGET>")
  set(CMAKE_CXX_ARCHIVE_FINISH "${CMAKE_C_ARCHIVE_FINISH}")
endif()

# make debug (environment variable from Makefile)
if(DEFINED ENV{DEBUG})
  set(DEBUG TRUE)
  set(CMAKE_BUILD_TYPE "Debug")
  if(WINDOWS)
    # TODO(#1985): Is there a MSVC flag congruent to -fstandalone-debug?
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
  # make sanitize (cannot make debug sanitize)
  set(SANITIZE_BLACKLIST "${CMAKE_SOURCE_DIR}/tools/analysis/sanitize_blacklist.txt")
  add_compile_options(
    -g
    -fstandalone-debug
    -fno-omit-frame-pointer
    -fno-optimize-sibling-calls
    -fsanitize-blacklist=${SANITIZE_BLACKLIST}
  )
  if (DEFINED ENV{SANITIZE_THREAD})
    add_compile_options(-fsanitize=thread)
  elseif(DEFINED ENV{SANITIZE_UNDEFINED})
    add_compile_options(-fsanitize=undefined)
  else()
    add_compile_options(-fsanitize=address)
    if(LINUX)
      # LSAN is not available on OS X 10.12.
      add_compile_options(-fsanitize=leak)
    endif()
  endif()

  if(LINUX)
    # Tests that fail TSAN Checks.
    set(SANITIZE_SKIP_TEST
      ProcessTests.test_launchExtension
      BufferedLogForwarderTests.test_index
      CarverTests.test_carve_files_locally
      FileEventsTableTests.*
      YARATest.*
    )
    string(REPLACE ";" ":" TEST_ARGS "${SANITIZE_SKIP_TEST}")
    set(TEST_ARGS "--gtest_filter=-${TEST_ARGS}")
  endif()
else()
  set(DEBUG FALSE)
  if(WINDOWS)
    add_compile_options(/Ot /WX)
  else()
    add_compile_options(-Os)
  endif()
  add_definitions(-DNDEBUG)
  # Do not enable fortify with clang: http://llvm.org/bugs/show_bug.cgi?id=16821
  #set(C_COMPILE_FLAGS "${C_COMPILE_FLAGS} -D_FORTIFY_SOURCE=2")

  # Visual Studio does not support generation of PIC code
  if(POSIX)
    # TSAN and MSAN do not like PIE/PIC on Linux 4.1.
    # To be safe, only include them when building 'release' outputs.
    add_compile_options(
      -fPIE
      -fpie
      -fPIC
      -fpic
    )
    if (CMAKE_CXX_COMPILER MATCHES "clang" AND NOT FREEBSD)
      # Only enable LTO builds when using clang on Unix, for now
      add_compile_options(-flto=thin)
    endif()
  endif()
endif()
# Generate a compile_commands.json for static analyzer input.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT DEFINED ENV{OPTIMIZED})
  if(WINDOWS)
    # It is unclear if AVX must be managed on Windows.
    add_compile_options(/favor:AMD64)
  else()
    add_compile_options(-march=x86-64 -mno-avx)
  endif()
endif()

# make analyze (environment variable from Makefile)
if(DEFINED ENV{ANALYZE})
  # TODO(#1985): clang-analyze on Windows
  if(WINDOWS)
    message(FATAL_ERROR "Cannot analyze on Windows right now." )
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

if(DEFINED ENV{FAST})
  set(ENV{OSQUERY_BUILD_SHARED} TRUE)
endif()

# make packages will set release to true and blacklist development features,
# development plugins, etc.
if(DEFINED ENV{PACKAGE})
  set(OSQUERY_BUILD_RELEASE TRUE)
else()
  set(OSQUERY_BUILD_RELEASE FALSE)
endif()

# Feature environment variables (flags), their use is highly discouraged.
# The recommended osquery build, and distributed packages, do not use these.
if(DEFINED ENV{SKIP_AWS})
  set(SKIP_AWS TRUE)
endif()
if(DEFINED ENV{SKIP_TSK})
  set(SKIP_TSK TRUE)
endif()
if(DEFINED ENV{SKIP_LLDPD})
  set(SKIP_LLDPD TRUE)
endif()
if(DEFINED ENV{SKIP_YARA})
  set(SKIP_YARA TRUE)
endif()
if(DEFINED ENV{SKIP_CARVER})
  set(SKIP_CARVER TRUE)
  # To remove references to carve functionality in sqlite helper functions
  add_definitions(
    -DSKIP_CARVER=1
  )
endif()

# Similar to the feature skips, there are default-build skips.
if(DEFINED ENV{SKIP_TESTS})
  set(SKIP_TESTS TRUE)
endif()
if(DEFINED ENV{SKIP_BENCHMARKS})
  set(SKIP_BENCHMARKS TRUE)
endif()
if(DEFINED ENV{SKIP_TABLES})
  set(SKIP_TABLES TRUE)
endif()

# Finished setting compiler/compiler flags.
project(OSQUERY)
set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY TRUE)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMake" "${CMAKE_MODULE_PATH}")
include(CMakeLibs)

find_program(CLANG_TIDY NAMES "clang-tidy" ENV PATH)
if(DEFINED ENV{TIDY} AND CLANG_TIDY)
  message(STATUS "clang-tidy found: ${CLANG_TIDY}")
  set(TIDY_CHECKS
    "*"
    "-cert-err58-cpp"
    "-cppcoreguidelines-pro-bounds-array-to-pointer-decay"
    "-readability-else-after-return"
    "-cppcoreguidelines-pro-type-union-access"
    "-modernize-use-bool-literals"
    "-modernize-use-emplace"
    "-google-runtime-references"
  )
  JOIN("${TIDY_CHECKS}" "," TIDY_CHECKS)
  set(DO_CLANG_TIDY "${CLANG_TIDY}"
    "-checks=${TIDY_CHECKS}"
    "-p=${CMAKE_BINARY_DIR}"
    "-fix"
  )
endif()

if(WINDOWS)
  foreach(flag_var
          CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
          CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
          CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO
          CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_RELWITHDEBINFO)
    if(${flag_var} MATCHES "/MD")
      string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
    endif(${flag_var} MATCHES "/MD")

    # Ignore unused parameter messages for C-based projects (e.g. sqlite3)
    if (flag_var MATCHES "^CMAKE_C_FLAGS*")
      set(${flag_var} "${${flag_var}} /wd4101")
    endif(flag_var MATCHES "^CMAKE_C_FLAGS*")
  endforeach(flag_var)

  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LTCG")
elseif(NOT FREEBSD)
  if (CMAKE_CXX_COMPILER MATCHES "clang")
    # Clang on Unix uses LTO; we also need to pass -flto when linking
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto=thin")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -flto=thin")
  endif()
endif()

if(NOT IS_DIRECTORY "${CMAKE_SOURCE_DIR}/third-party/sqlite3")
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
  -DNOMINMAX

  # See boost 1.65 breakage https://github.com/Homebrew/homebrew-core/pull/17150
  -D__ASSERT_MACROS_DEFINE_VERSIONS_WITHOUT_UNDERSCORES=0
)

# Remove console output (not handled by logged).
add_definitions(-DTHRIFT_SQUELCH_CONSOLE_OUTPUT=1)

if(DEFINED ENV{SQLITE_DEBUG})
  add_definitions(
    -DSQLITE_DEBUG=1
    -DSQLITE_ENABLE_WHERETRACE=1
  )
endif()

if(APPLE)
  LOG_PLATFORM("OS X")
elseif(OSQUERY_BUILD_PLATFORM STREQUAL "debian")
  LOG_PLATFORM("Debian")
elseif(OSQUERY_BUILD_PLATFORM STREQUAL "ubuntu")
  LOG_PLATFORM("Ubuntu")
elseif(OSQUERY_BUILD_PLATFORM STREQUAL "centos")
  LOG_PLATFORM("CentOS")
elseif(OSQUERY_BUILD_PLATFORM STREQUAL "scientific")
  LOG_PLATFORM("Scientific Linux")
elseif(OSQUERY_BUILD_PLATFORM STREQUAL "rhel")
  LOG_PLATFORM("RHEL")
elseif(OSQUERY_BUILD_PLATFORM STREQUAL "amazon")
  LOG_PLATFORM("Amazon Linux")
elseif(OSQUERY_BUILD_PLATFORM STREQUAL "oracle")
  LOG_PLATFORM("Oracle Linux")
elseif(OSQUERY_BUILD_PLATFORM STREQUAL "gentoo")
  LOG_PLATFORM("Gentoo Linux")
elseif(OSQUERY_BUILD_PLATFORM STREQUAL "funtoo")
  LOG_PLATFORM("Funtoo Linux")
elseif(OSQUERY_BUILD_PLATFORM STREQUAL "freebsd")
  LOG_PLATFORM("FreeBSD")
elseif(OSQUERY_BUILD_PLATFORM STREQUAL "windows")
  LOG_PLATFORM("Windows")
endif()

# Add sysroot overrides for each platform/distro.
# These should be prioritized over all other includes.
if(APPLE)
  include_directories(SYSTEM "${CMAKE_SOURCE_DIR}/third-party/sysroots/darwin")
elseif(LINUX)
  include_directories(SYSTEM "${CMAKE_SOURCE_DIR}/third-party/sysroots/linux")
endif()

if(POSIX)
  include_directories(SYSTEM "${BUILD_DEPS}/legacy/include")
  include_directories(SYSTEM "${BUILD_DEPS}/include")
  include_directories("${BUILD_DEPS}/include/openssl")
endif()

include_directories("${CMAKE_SOURCE_DIR}/third-party/sqlite3")
include_directories("${CMAKE_SOURCE_DIR}/include")
include_directories("${CMAKE_SOURCE_DIR}")

set(MKDIR_OPTS "")
if(WINDOWS)
  set(PROCESS_FAMILY "windows")

  # Win64 specific gflags
  set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build static gtest/gmock library" FORCE)

  file(GLOB INCLUDE_DIRS LIST_DIRECTORIES true "${WINDOWS_DEP_DIR}/*/*/include")
  include_directories(SYSTEM ${INCLUDE_DIRS})
  include_directories(SYSTEM "${WINDOWS_DEP_DIR}/boost-msvc14/local")

  ## TODO(FIXME): temporary for now
  include_directories("${WINDOWS_DEP_DIR}/linenoise-ng/local/include/linenoise")
else()
  set(PROCESS_FAMILY "posix")
  set(MKDIR_OPTS "-p")
endif()

if(WINDOWS)
  foreach(DEP_DIR ${WINDOWS_DEP_LIST})
    file(GLOB_RECURSE WINDOWS_LOCAL_LIB_DIRS LIST_DIRECTORIES false "${DEP_DIR}/*.lib")
    foreach(LIB_FILE ${WINDOWS_LOCAL_LIB_DIRS})
      get_filename_component(LIB_DIR ${LIB_FILE} DIRECTORY)
      list(APPEND OS_LIB_DIRS ${LIB_DIR})
    endforeach()
  endforeach()
  list(REMOVE_DUPLICATES OS_LIB_DIRS)
  link_directories(${OS_LIB_DIRS})
else()
  set(OS_LIB_DIRS
    "/lib"
    "/lib64"
    "/usr/lib"
    "/usr/lib64"
    "/usr/lib/x86_64-linux-gnu/"
    )
endif()

# Make sure the generated paths exist
execute_process(COMMAND mkdir ${MKDIR_OPTS} "${CMAKE_BINARY_DIR}/generated")

# We need to link some packages as dynamic/dependent.
set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .dylib .so .a)
set(CMAKE_SKIP_RPATH TRUE)

# FreeBSD does not use the osquery build system, link discovered libraries.
if(FREEBSD)
  set(ENV{BUILD_LINK_SHARED} TRUE)
endif()

# Most dependent packages/libs we want static.
if(DEFINED ENV{BUILD_LINK_SHARED})
  set(ENV{OSQUERY_BUILD_LINK_SHARED} TRUE)
endif()
if(NOT DEFINED ENV{OSQUERY_BUILD_LINK_SHARED})
  set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .a .dylib .so)
endif()

# Previously, this would find_package for Gtest.
# We can supply the known include paths within each test as compile flags.
enable_testing()
set(CTEST_TEST_TIMEOUT 600)

# Detect TR1 usage.
include(CheckIncludeFileCXX)
if(WINDOWS)
  check_include_file_cxx("tuple" HAVE_TR1_TUPLE)
else()
  check_include_file_cxx("tr1/tuple" HAVE_TR1_TUPLE)
endif()

if(FREEBSD OR "${HAVE_TR1_TUPLE}" STREQUAL "")
  set(GTEST_FLAGS "-DGTEST_USE_OWN_TR1_TUPLE=1")
else()
  set(GTEST_FLAGS "-DGTEST_USE_OWN_TR1_TUPLE=0")
endif()

set(GTEST_FLAGS
  ${GTEST_FLAGS}
  "-I${CMAKE_SOURCE_DIR}/third-party/googletest/googletest/include"
  "-I${CMAKE_SOURCE_DIR}/third-party/googletest/googlemock/include"
)
join("${GTEST_FLAGS}" " " GTEST_FLAGS)

set(BUILD_GTEST TRUE)

add_subdirectory("${CMAKE_SOURCE_DIR}/third-party/googletest")

include(Thrift)

add_subdirectory("${CMAKE_SOURCE_DIR}/third-party/sqlite3")

add_subdirectory(osquery)
add_subdirectory(tools/tests)

# Include the kernel building targets/macros
if(NOT ${OSQUERY_BUILD_SDK_ONLY})
  add_subdirectory(kernel)
endif()

# Packages must be included after all other CMake includes.
if(NOT ${OSQUERY_BUILD_SDK_ONLY})
  include(Packages)
endif()

# make docs
add_custom_target(
  docs
  COMMAND "${PYTHON_EXECUTABLE}"
    "${CMAKE_SOURCE_DIR}/tools/codegen/genapi.py" "${CMAKE_SOURCE_DIR}"
    "--output" "--directory" "${CMAKE_SOURCE_DIR}/build/docs"
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  COMMENT "Generating API documentation with Doxygen/mkdocs" VERBATIM
)

find_program(DOXYGEN_EXECUTABLE doxygen ENV PATH)
if(DOXYGEN_EXECUTABLE)
  add_custom_command(TARGET docs POST_BUILD
    COMMAND echo "PROJECT_NUMBER=${OSQUERY_BUILD_VERSION}" |
      cat ${CMAKE_SOURCE_DIR}/Doxyfile - | "${DOXYGEN_EXECUTABLE}" -;
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  )
else(DEFINED ENV{DOCS})
  WARNING_LOG("Cannot find Doxygen executable in path")
endif()

find_program(MKDOCS_EXECUTABLE mkdocs ENV PATH)
if(MKDOCS_EXECUTABLE)
  add_custom_command(TARGET docs POST_BUILD
    COMMAND "${MKDOCS_EXECUTABLE}" build --clean -s
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  )
elseif(DEFINED ENV{DOCS})
  WARNING_LOG("Cannot find mkdocs executable in path")
endif()

# make format-all
find_program(CLANGFORMAT_EXECUTABLE "clang-format" ENV PATH)
add_custom_target(
  format_all
  find osquery include tools \( -name "*.h" -o -name "*.cpp" -o -name "*.mm" \)
    -exec "${CLANGFORMAT_EXECUTABLE}" -i {} +
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  COMMENT "Formatting all osquery code with clang-format" VERBATIM
)

# make format
add_custom_target(
  format
  "${PYTHON_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/tools/formatting/git-clang-format.py" "-f" "--binary" "${BUILD_DEPS}/bin/clang-format"
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
