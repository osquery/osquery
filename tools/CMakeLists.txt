# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(toolsMain)
  add_subdirectory("codegen")
  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

if(DEFINED PLATFORM_WINDOWS)
  set(TOOLS_WEL_FILES_ROOT_DIR "${CMAKE_CURRENT_BINARY_DIR}" CACHE INTERNAL "")

  getCleanedOsqueryVersion("osquery_version")
  getCleanedOsqueryVersionComponents("osquery_version_major" "osquery_version_minor" "osquery_version_patch")

  set(osquery_rc_MSG "${TOOLS_WEL_FILES_ROOT_DIR}/wel/MSG00001.bin")
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/wel/MSG00001.bin"
    "${osquery_rc_MSG}"
    COPYONLY
  )

  set(osquery_rc_WEVT_TEMPLATE "${TOOLS_WEL_FILES_ROOT_DIR}/wel/osqueryTEMP.BIN")
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/wel/osqueryTEMP.BIN"
    "${osquery_rc_WEVT_TEMPLATE}"
    COPYONLY
  )

  set(osquery_rc "${TOOLS_WEL_FILES_ROOT_DIR}/wel/osquery.rc")
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/wel/osquery.rc.in"
    "${osquery_rc}"
    @ONLY
  )

  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/windows_resources.rc.in"
    "${TOOLS_WEL_FILES_ROOT_DIR}/windows_resources.rc"
    @ONLY
  )
endif()
endfunction()

toolsMain()
