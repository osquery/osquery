# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(generateOsqueryTablesApplicationsTestsApplicationsTablesTestsTest)
  add_osquery_executable(osquery_tables_applications_tests_applicationstablestests-test
    ai_assistant_chats/antigravity_tests.cpp
    ai_assistant_chats/claude_tests.cpp
    ai_assistant_chats/codex_tests.cpp
    ai_assistant_chats/copilot_cli_tests.cpp
    ai_assistant_chats/cursor_tests.cpp
    ai_assistant_chats/gemini_tests.cpp
    ai_assistant_chats/kimi_tests.cpp
    ai_assistant_chats/pi_tests.cpp
    ai_assistant_chats/transcript_tests.cpp
    ai_assistant_chats/utils_tests.cpp
    ai_assistant_chats/vscode_tests.cpp
    jetbrains_plugins_tests.cpp
  )

  target_link_libraries(osquery_tables_applications_tests_applicationstablestests-test PRIVATE
    osquery_cxx_settings
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_tables_applications
    tests_helper
    thirdparty_googletest
  )

  add_test(NAME osquery_tables_applications_tests_applicationstablestests-test
           COMMAND osquery_tables_applications_tests_applicationstablestests-test)
endfunction()

generateOsqueryTablesApplicationsTestsApplicationsTablesTestsTest()
