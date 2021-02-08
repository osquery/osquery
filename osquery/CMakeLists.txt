# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryMain)
  add_subdirectory("process")
  add_subdirectory("profiler")
  add_subdirectory("dispatcher")
  add_subdirectory("sql")
  add_subdirectory("sdk")
  add_subdirectory("numeric_monitoring")
  add_subdirectory("registry")
  add_subdirectory("logger")
  add_subdirectory("distributed")
  add_subdirectory("carver")
  add_subdirectory("tables")
  add_subdirectory("hashing")
  add_subdirectory("remote")
  add_subdirectory("core")
  add_subdirectory("config")
  add_subdirectory("utils")
  add_subdirectory("filesystem")
  add_subdirectory("database")
  add_subdirectory("main")
  add_subdirectory("devtools")
  add_subdirectory("extensions")
  add_subdirectory("events")
  add_subdirectory("experimental")
  add_subdirectory("system")
  add_subdirectory("worker")

  generateOsqueryd()
endfunction()

function(generateOsqueryd)
  # Upstream uses an empty executable that links to a library with a
  # a main() entry point; try to emulate this.
  set(source_file "${CMAKE_CURRENT_BINARY_DIR}/empty_osqueryd_target_source_file.cpp")
  generateBuildTimeSourceFile(${source_file} "extern int main(int argc, char* argv[]);")

  add_osquery_executable(osqueryd "${source_file}")
  set_target_properties(osqueryd PROPERTIES POSITION_INDEPENDENT_CODE true)

  target_link_libraries(osqueryd PRIVATE
    osquery_cxx_settings
    osquery_main
  )

  set(osquery_ext "")
  if(PLATFORM_WINDOWS)
    set(osquery_ext ".exe")
  endif()

  add_custom_target(create_osqueryi ALL DEPENDS osqueryi${osquery_ext})
  add_custom_command(OUTPUT osqueryi${osquery_ext}
    COMMAND "${CMAKE_COMMAND}" -E create_symlink osqueryd${osquery_ext} osqueryi${osquery_ext}
    WORKING_DIRECTORY "$<TARGET_FILE_DIR:osqueryd>"
  )
  add_dependencies(create_osqueryi osqueryd)
endfunction()

function(enableOsqueryWEL)
  target_sources(osqueryd PRIVATE "${TOOLS_WEL_FILES_ROOT_DIR}/windows_resources.rc")
endfunction()

osqueryMain()
