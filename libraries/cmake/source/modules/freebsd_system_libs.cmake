# Copyright (c) 2014-present, The osquery authors
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
#
# FreeBSD-only helper: create a thirdparty_<name> INTERFACE target that
# links against FreeBSD system libraries (base + ports) instead of
# building osquery's vendored copy.  osquery's importLibraries() in
# CMakeLists.txt then takes path #1 ("if(TARGET thirdparty_<name>)") and
# does not invoke find_package() for a source build.
#
# Why per-lib IMPORTED targets rather than absolute paths:
# osquery's add_real_target_dependencies() (cmake/utilities.cmake) walks
# INTERFACE_LINK_LIBRARIES and calls get_target_property(... TYPE) on each
# entry.  Absolute paths like /usr/local/lib/liblz4.so are not CMake
# targets — that produces a flood of "non-existent target" CMake errors.
# By wrapping each system library in a SHARED IMPORTED target, the walker
# sees a real target with TYPE=SHARED_LIBRARY and proceeds cleanly.

function(freebsd_use_system_lib name)
  cmake_parse_arguments(ARG "" "" "LIBS;INCLUDES;DEFINITIONS" ${ARGN})

  if(TARGET "thirdparty_${name}")
    return()
  endif()

  set(imported_targets)
  foreach(lib ${ARG_LIBS})
    find_library(${name}_${lib}_LIB ${lib} REQUIRED)
    set(imp_target "thirdparty_${name}_${lib}")
    if(NOT TARGET ${imp_target})
      add_library(${imp_target} SHARED IMPORTED GLOBAL)
      set_target_properties(${imp_target} PROPERTIES
        IMPORTED_LOCATION "${${name}_${lib}_LIB}"
      )
    endif()
    list(APPEND imported_targets ${imp_target})
  endforeach()

  add_library("thirdparty_${name}" INTERFACE)

  if(imported_targets)
    target_link_libraries("thirdparty_${name}" INTERFACE ${imported_targets})
  endif()

  if(ARG_INCLUDES)
    target_include_directories("thirdparty_${name}" SYSTEM INTERFACE ${ARG_INCLUDES})
  endif()

  if(ARG_DEFINITIONS)
    target_compile_definitions("thirdparty_${name}" INTERFACE ${ARG_DEFINITIONS})
  endif()
endfunction()
