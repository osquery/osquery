# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryToolsTestsMain)
  if(OSQUERY_BUILD_TESTS)
    set(configs_base_path "${CMAKE_CURRENT_SOURCE_DIR}/configs")
    generateCopyFileTarget("osquery_tools_tests_configfiles" "${configs_base_path}" "REGEX" "*" "${TEST_CONFIGS_DIR}")
    generatePythonTests()
  endif()
endfunction()

function(addPythonTest)
  set(oneValueArgs NAME SCRIPT)
  set(multiValueArgs EXTRA_ARGS ARGS)
  cmake_parse_arguments(PARSE_ARGV 0 osquery_test "" "${oneValueArgs}" "${multiValueArgs}")

  if(DEFINED osquery_test_EXTRA_ARGS AND DEFINED osquery_test_ARGS)
    message(FATAL_ERROR "Only one of ARGS and EXTRA_ARGS can be used to declare a python test")
  endif()

  set(test_args
    --verbose
    --build "${CMAKE_BINARY_DIR}"
    --test-configs-dir "${TEST_CONFIGS_DIR}"
  )

  if(DEFINED osquery_test_EXTRA_ARGS)
    list(APPEND test_args
      ${osquery_test_EXTRA_ARGS}
    )
  elseif(DEFINED osquery_test_ARGS)
    set(test_args ${osquery_test_ARGS})
  endif()

  get_filename_component(script_name "${osquery_test_SCRIPT}" NAME)

  configure_file("${osquery_test_SCRIPT}" ${script_name} COPYONLY)

  set(python_test_command
    "${CMAKE_COMMAND}" -E env "PYTHONPATH=${OSQUERY_PYTHON_PATH}"
    "${OSQUERY_PYTHON_EXECUTABLE}" -u ${script_name}
    "${test_args}"
  )

  add_test(NAME ${osquery_test_NAME}
    COMMAND ${python_test_command}
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")

  set_tests_properties(${osquery_test_NAME} PROPERTIES TIMEOUT 300)
endfunction()

function(preparePythonTestsEnvironment)
  # Common files and scripts needed by the tests
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/test_base.py" test_base.py COPYONLY)
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/utils.py" utils.py COPYONLY)
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/test_http_server.py" test_http_server.py COPYONLY)
  configure_file("${CMAKE_SOURCE_DIR}/tools/deployment/osquery.example.conf" "${TEST_CONFIGS_DIR}/osquery.example.conf" COPYONLY)

  add_custom_target(osquery_tools_tests_pythontests ALL)

  # The test test_example_queries requires to use codegen scripts, let's copy them in the binary dir
  generateCopyFileTarget("osquery_tools_codegen_scripts" "${CMAKE_SOURCE_DIR}/tools/codegen" "REGEX" "gen*.py" "${CMAKE_CURRENT_BINARY_DIR}")

  # TODO: Uncomment me when the query packs test is fully fixed
  # generateCopyFileTarget("osquery_tools_tests_copy_query_packs" "${CMAKE_SOURCE_DIR}/packs" "REGEX" "*.conf" "${TEST_CONFIGS_DIR}/packs")

  # Also prepare a proper module path for utils.py
  if(PLATFORM_WINDOWS)
    configure_file("${CMAKE_SOURCE_DIR}/tools/tests/winexpect.py" winexpect.py COPYONLY)
  endif()

  add_dependencies(osquery_tools_tests_pythontests osqueryd)
  add_dependencies(osquery_tools_tests_pythontests osquery_tools_tests_configfiles)
  add_dependencies(osquery_tools_tests_pythontests osquery_tools_codegen_scripts)
  add_dependencies(osquery_tools_tests_pythontests specs_table_files)
  add_dependencies(osquery_tools_tests_pythontests codegen_gentable_utils_dependency)
  add_dependencies(osquery_tools_tests_pythontests create_osqueryi)

  # TODO: Uncomment me when the query packs test is fully fixed
  # add_dependencies(osquery_tools_tests_pythontests osquery_tools_tests_copy_query_packs)
endfunction()

function(generatePythonTests)

  preparePythonTestsEnvironment()

  # Tests
  addPythonTest(NAME tools_tests_testosqueryd SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/test_osqueryd.py")
  addPythonTest(NAME tools_tests_testosqueryi SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/test_osqueryi.py")

  set(release_test_args
    "--build_dir=${CMAKE_BINARY_DIR}"
    "--verbose"
  )

  # TODO: Add back this test once the zlib .so is no longer linked by the BPF libraries
  # addPythonTest(NAME tools_tests_testrelease SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/test_release.py" ARGS ${release_test_args})

  # TODO: Uncomment me when the query packs test is fully fixed
  # addPythonTest(NAME tools_tests_testquerypacks SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/test_query_packs.py")

  if(PLATFORM_LINUX)
    addPythonTest(NAME tools_tests_testfschangestable SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/test_docker_container_fs_changes_table.py")
  endif()
endfunction()

osqueryToolsTestsMain()
