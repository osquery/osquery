# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryToolsTestsMain)
  if(OSQUERY_BUILD_TESTS)
    set(configs_base_path "${CMAKE_CURRENT_SOURCE_DIR}/configs")
    generateCopyFileTarget("osquery_tools_tests_conffiles" "${configs_base_path}" "REGEX" "*.conf" "${TEST_CONFIGS_DIR}")
    generateCopyFileTarget("osquery_tools_tests_configfiles" "${configs_base_path}" "REGEX" "*.config" "${TEST_CONFIGS_DIR}")
    generateCopyFileTarget("osquery_tools_tests_plistfiles" "${configs_base_path}" "REGEX" "*.plist" "${TEST_CONFIGS_DIR}")
    generateCopyFileTarget("osquery_tools_tests_testfiles" "${configs_base_path}" "REGEX" "*" "${TEST_CONFIGS_DIR}")
    generateCopyFileTarget("osquery_tools_tests_awsfiles" "${configs_base_path}" "REGEX" "aws/*" "${TEST_CONFIGS_DIR}")
    generatePythonTests()
  endif()
endfunction()

function(addPythonTest)
  set(oneValueArgs NAME SCRIPT)
  set(multiValueArgs EXTRA_ARGS)
  cmake_parse_arguments(PARSE_ARGV 0 osquery_test "" "${oneValueArgs}" "${multiValueArgs}")

  get_filename_component(script_name "${osquery_test_SCRIPT}" NAME)

  configure_file("${osquery_test_SCRIPT}" ${script_name} COPYONLY)

  set(python_test_command
    "${CMAKE_COMMAND}" -E env "PYTHONPATH=${OSQUERY_PYTHON_PATH}"
    "${Python3_EXECUTABLE}" -u ${script_name} --verbose --build "${CMAKE_BINARY_DIR}" --test-configs-dir "${TEST_CONFIGS_DIR}" "${osquery_test_EXTRA_ARGS}")

  add_test(NAME ${osquery_test_NAME}
    COMMAND ${python_test_command}
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")

  set_tests_properties(${osquery_test_NAME} PROPERTIES TIMEOUT 30)
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

  # Also prepare a proper module path for utils.py
  if(PLATFORM_WINDOWS)
    configure_file("${CMAKE_SOURCE_DIR}/tools/tests/winexpect.py" winexpect.py COPYONLY)
  endif()

  add_dependencies(osquery_tools_tests_pythontests osqueryd)
  add_dependencies(osquery_tools_tests_pythontests osquery_tools_tests_testfiles)
  add_dependencies(osquery_tools_tests_pythontests osquery_tools_codegen_scripts)
  add_dependencies(osquery_tools_tests_pythontests specs_table_files)
  add_dependencies(osquery_tools_tests_pythontests codegen_gentable_utils_dependency)
  add_dependencies(osquery_tools_tests_pythontests create_osqueryi)
endfunction()

function(generatePythonTests)

  preparePythonTestsEnvironment()

  # Tests
  addPythonTest(NAME tools_tests_testosqueryd SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/test_osqueryd.py")

  addPythonTest(NAME tools_tests_testosqueryi SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/test_osqueryi.py")
  set_tests_properties(tools_tests_testosqueryi PROPERTIES TIMEOUT 120)

  addPythonTest(NAME tools_tests_testrelease SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/test_release.py")

  if(DEFINED PLATFORM_WINDOWS)
    addPythonTest(NAME tools_tests_testwindowsservice SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/test_windows_service.py")
    set_tests_properties(tools_tests_testwindowsservice PROPERTIES TIMEOUT 120)
  else()
    addPythonTest(NAME tools_tests_testadditional SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/test_additional.py")

    addPythonTest(NAME tools_tests_testexamplequeries SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/test_example_queries.py")

    # The following tests need to be restored when extensions work again
    addPythonTest(NAME tools_tests_testextensions SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/test_extensions.py")
    set_tests_properties(tools_tests_testextensions PROPERTIES DISABLED TRUE)
  endif()
endfunction()

osqueryToolsTestsMain()
