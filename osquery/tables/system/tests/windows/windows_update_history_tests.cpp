/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/tables/system/windows/windows_update_history.h>

namespace osquery {

namespace tables {

class WindowsUpdateHistoryTests : public testing::Test {};

WindowsUpdateHistory generateTestHistory() {
  tables::WindowsUpdateHistoryEntry e = {
      "ClientAppID",
      0,
      "Description",
      S_OK,
      uoInstallation,
      orcNotStarted,
      ssDefault,
      "ServiceID",
      "SupportUrl",
      "Title",
      "UpdateID",
      0,
  };

  WindowsUpdateHistory history;

  WindowsUpdateHistoryEntry entry;
  entry = e;
  history.push_back(entry);

  entry = e;
  entry.updateOp = uoUninstallation;
  history.push_back(entry);

  entry = e;
  entry.resultCode = orcInProgress;
  history.push_back(entry);

  entry = e;
  entry.resultCode = orcSucceeded;
  history.push_back(entry);

  entry = e;
  entry.resultCode = orcSucceededWithErrors;
  history.push_back(entry);

  entry = e;
  entry.resultCode = orcFailed;
  history.push_back(entry);

  entry = e;
  entry.resultCode = orcAborted;
  history.push_back(entry);

  entry = e;
  entry.serverSelection = ssManagedServer;
  history.push_back(entry);

  entry = e;
  entry.serverSelection = ssWindowsUpdate;
  history.push_back(entry);

  entry = e;
  entry.serverSelection = ssOthers;
  history.push_back(entry);
  return history;
}

void validateRendered(const WindowsUpdateHistoryEntry& entry, Row& row) {
  ASSERT_EQ(row["client_app_id"], entry.clientAppID);
  ASSERT_EQ(row["date"], BIGINT(entry.date));
  ASSERT_EQ(row["description"], entry.description);
  ASSERT_EQ(row["hresult"], BIGINT(entry.hresult));

  switch (entry.updateOp) {
  case uoInstallation:
    ASSERT_EQ(row["operation"], "Installation");
    break;
  case uoUninstallation:
    ASSERT_EQ(row["operation"], "Uninstallation");
    break;
  default:
    ASSERT_EQ(row["operation"], "");
    break;
  }

  switch (entry.resultCode) {
  case orcNotStarted:
    ASSERT_EQ(row["result_code"], "NotStarted");
    break;
  case orcInProgress:
    ASSERT_EQ(row["result_code"], "InProgress");
    break;
  case orcSucceeded:
    ASSERT_EQ(row["result_code"], "Succeeded");
    break;
  case orcSucceededWithErrors:
    ASSERT_EQ(row["result_code"], "SucceededWithErrors");
    break;
  case orcFailed:
    ASSERT_EQ(row["result_code"], "Failed");
    break;
  case orcAborted:
    ASSERT_EQ(row["result_code"], "Aborted");
    break;
  default:
    ASSERT_EQ(row["result_code"], "");
    break;
  }

  switch (entry.serverSelection) {
  case ssDefault:
    ASSERT_EQ(row["server_selection"], "Default");
    break;
  case ssManagedServer:
    ASSERT_EQ(row["server_selection"], "ManagedServer");
    break;
  case ssWindowsUpdate:
    ASSERT_EQ(row["server_selection"], "WindowsUpdate");
    break;
  case ssOthers:
    ASSERT_EQ(row["server_selection"], "Others");
    break;
  default:
    ASSERT_EQ(row["server_selection"], "");
    break;
  }

  ASSERT_EQ(row["service_id"], entry.serviceID);
  ASSERT_EQ(row["support_url"], entry.supportUrl);
  ASSERT_EQ(row["title"], entry.title);
  ASSERT_EQ(row["update_id"], entry.updateID);
  ASSERT_EQ(row["update_revision"], BIGINT(entry.updateRevision));
}

// } // namespace

TEST_F(WindowsUpdateHistoryTests, test_update_history_render) {
  auto history = generateTestHistory();
  auto rows = renderWindowsUpdateHistory(history);

  ASSERT_EQ(rows.size(), history.size());

  size_t i = 0;
  std::for_each(history.cbegin(),
                history.cend(),
                [&](const WindowsUpdateHistoryEntry& entry) {
                  auto row = rows[i++];
                  validateRendered(entry, row);
                });
}

} // namespace tables
} // namespace osquery