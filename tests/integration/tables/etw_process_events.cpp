/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for process_events
// Spec file: specs/posix/process_events.table

#include <osquery/config/config.h>
#include <osquery/dispatcher/dispatcher.h>
#include <osquery/events/events.h>
#include <osquery/registry/registry.h>
#include <osquery/tests/integration/tables/helper.h>

namespace osquery {

DECLARE_bool(enable_etw_process_events);

namespace table_tests {

class etwProcessEvents : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();

    // Enable ETW process events
    RegistryFactory::get().registry("config_parser")->setUp();
    FLAGS_enable_etw_process_events = true;

    // Start eventing framework
    attachEvents();
  }

  void TearDown() override {
    Dispatcher::instance().stopServices();
    Dispatcher::instance().joinServices();
    Dispatcher::instance().resetStopping();
  }
};

TEST_F(etwProcessEvents, test_sanity) {
  // 1. Launching process to generate ProcessStart and ProcessStop events
  system("logman.exe query -ets > NUL");
  Sleep(4000);

  // 2. Query data
  auto const data = execute_query(
      "select type, pid, ppid, session_id, flags, exit_code, path, cmdline, "
      "username, token_elevation_type, token_elevation_status, "
      "mandatory_label, datetime, time_windows, time, eid, header_pid, "
      "process_sequence_number, parent_process_sequence_number from "
      "etw_process_events");

  // 3. Check size before validation
  ASSERT_GE(data.size(), 0ul);

  // 4. Build validation map
  ValidationMap row_map = {
      {"type", NonEmptyString},
      {"pid", NonNegativeInt},
      {"ppid", NonNegativeInt},
      {"session_id", NonNegativeInt},
      {"flags", NonNegativeInt},
      {"exit_code", EmptyOk | NullOk},
      {"path", NonEmptyString},
      {"cmdline", EmptyOk | NullOk},
      {"username", NonEmptyString},
      {"token_elevation_type", EmptyOk | NullOk},
      {"token_elevation_status", EmptyOk | NullOk},
      {"mandatory_label", EmptyOk | NullOk},
      {"datetime", NonNegativeInt},
      {"time_windows", NonNegativeInt},
      {"time", NonNegativeInt},
      {"eid", NonNegativeInt},
      {"header_pid", NonNegativeInt},
      {"process_sequence_number", NonNegativeInt},
      {"parent_process_sequence_number", EmptyOk | NullOk}};

  // 5. Perform validation
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
