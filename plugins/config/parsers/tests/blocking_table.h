/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

#include <osquery/core/tables.h>
#include <osquery/registry/registry.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/sql/sqlite_util.h>

namespace osquery {

/**
 * A one-column table whose generate() blocks until the test releases it.
 *
 * Tests use it to pause a query at a known point (after the code under test
 * has started the query, before its results are published) and then act on
 * another thread while it is paused, instead of relying on timing.
 */
class BlockingTablePlugin : public TablePlugin {
 public:
  explicit BlockingTablePlugin(std::string value) : value_(std::move(value)) {}

  /// Wait until a query is inside generate().
  bool waitUntilEntered(std::chrono::seconds timeout) {
    return entered_future_.wait_for(timeout) == std::future_status::ready;
  }

  /// Let generate() return its row. Safe to call more than once.
  void release() {
    std::call_once(release_once_, [this] { release_.set_value(); });
  }

 private:
  TableColumns columns() const override {
    return {std::make_tuple("value", TEXT_TYPE, ColumnOptions::DEFAULT)};
  }

  TableRows generate(QueryContext&) override {
    if (!entered_.exchange(true)) {
      entered_promise_.set_value();
    }
    release_future_.wait();

    TableRows rows;
    rows.push_back(make_table_row({{"value", value_}}));
    return rows;
  }

  const std::string value_;

  std::atomic<bool> entered_{false};
  std::promise<void> entered_promise_;
  std::future<void> entered_future_{entered_promise_.get_future()};

  std::once_flag release_once_;
  std::promise<void> release_;
  std::shared_future<void> release_future_{release_.get_future().share()};
};

/**
 * Register a BlockingTablePlugin as `name` and attach it to SQLite.
 *
 * Each call needs a new name, since a registry name and an attached table
 * cannot be replaced. Returns nullptr on failure.
 */
inline std::shared_ptr<BlockingTablePlugin> attachBlockingTable(
    const std::string& name, const std::string& value) {
  // Make sure the primary connection exists first. Creating it attaches every
  // registered table, so creating it after registering would attach this
  // table twice, and the explicit attach below would fail.
  SQLiteDBManager::get();

  auto table = std::make_shared<BlockingTablePlugin>(value);
  if (!RegistryFactory::get().registry("table")->add(name, table).ok()) {
    return nullptr;
  }

  // Attach to the primary connection, as extension tables are. Queries that
  // cannot get the primary connection, because the blocked query holds it,
  // use a transient connection that attaches every registered table,
  // including this one.
  if (!Registry::call("sql", "sql", {{"action", "attach"}, {"table", name}})
           .ok()) {
    return nullptr;
  }
  return table;
}

/// Releases a BlockingTablePlugin when destroyed, so that a failed assertion
/// cannot leave a worker blocked. Declare it after the futures of the
/// workers that query the table, so it is destroyed, and releases the table,
/// before those futures wait for their workers.
struct BlockingTableReleaser {
  std::shared_ptr<BlockingTablePlugin> table;
  ~BlockingTableReleaser() {
    table->release();
  }
};

} // namespace osquery
