/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for ai_assistant_chats
// Spec file: specs/ai_assistant_chats.table

#include <osquery/dispatcher/dispatcher.h>
#include <osquery/logger/logger.h>
#include <osquery/tests/integration/tables/helper.h>
#include <osquery/tests/test_util.h>

namespace osquery {
namespace table_tests {

class aiAssistantChats : public testing::Test {
 protected:
  /**
   * @brief Initializes the test environment before each test.
   */
  void SetUp() override {
    setUpEnvironment();
  }

#ifdef OSQUERY_WINDOWS
  static void SetUpTestSuite() {
    initUsersAndGroupsServices(true, false);
  }

  /**
   * @brief Stops dispatcher services and deinitializes user and group services after the test suite.
   */
  static void TearDownTestSuite() {
    Dispatcher::stopServices();
    Dispatcher::joinServices();
    deinitUsersAndGroupsServices(true, false);
    Dispatcher::instance().resetStopping();
  }
#endif
};

/**
 * @brief Validates the schema values and contents of rows in the AI assistant chats table.
 */
TEST_F(aiAssistantChats, test_sanity) {
  auto const data = execute_query("select * from ai_assistant_chats");
  if (data.empty()) {
    LOG(WARNING) << "Empty results of query from 'ai_assistant_chats', assume "
                    "there is no AI assistant chat history on the system";
    return;
  }

  ValidationMap row_map = {
      {"application",
       SpecificValuesCheck{"claude_code",
                           "claude_desktop",
                           "codex",
                           "gemini_cli",
                           "cursor",
                           "copilot",
                           "antigravity"}},
      {"session_id", NonEmptyString},
      {"role", SpecificValuesCheck{"user", "assistant"}},
      {"message", NonEmptyString},
      {"timestamp", NonNegativeInt},
      {"path", NonEmptyString},
      {"uid", NonNegativeInt},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
