/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/system.h>
#include <osquery/sdk/sdk.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/json/json.h>

#include <mutex>
#include <sstream>

using namespace osquery;
class WritableTable : public TablePlugin {
 private:
  /// Simple primary key implementation; this is just the two columns
  /// concatenated
  using PrimaryKey = std::string;

  /// A rowid value uniquely identifies a row in a table
  using RowID = std::string;

  /// Data mutex
  std::mutex mutex;

  /// This is our data; each row contains a rowid, and the two remaining columns
  /// ('text' and 'integer')
  std::unordered_map<PrimaryKey, Row> data;

  /// This is used to map rowids to primary keys
  std::unordered_map<RowID, PrimaryKey> rowid_to_primary_key;

  /// This is an example implementation for a basic primary key
  PrimaryKey getPrimaryKey(const Row& row) const {
    return row.at("text") + row.at("integer");
  }

  /// Returns true if the given primary key is unique; used to adhere to
  /// constraints
  bool isPrimaryKeyUnique(
      const PrimaryKey& primary_key,
      const std::string& ignored_rowid = std::string()) const {
    auto it = data.find(primary_key);
    if (it == data.end()) {
      return true;
    }

    if (ignored_rowid.empty()) {
      return false;
    }

    return it->second.at("rowid") == ignored_rowid;
  }

  /// Generates a new rowid value; used when sqlite3 does not provide one
  size_t generateRowId() const {
    static size_t rowid_generator = 0U;
    return rowid_generator++;
  }

  /// Saves the given row
  Status saveRow(const Row& row, PrimaryKey primary_key = std::string()) {
    // Expect full rows (i.e. must include the rowid column)
    if (row.size() != 3U) {
      return Status(1, "Invalid column count");
    }

    // Compute the primary key if we haven't received one
    if (primary_key.empty()) {
      primary_key = getPrimaryKey(row);
    }

    // Save the row and update the index
    data.insert({primary_key, row});

    const auto& rowid = row.at("rowid");
    rowid_to_primary_key.insert({rowid, primary_key});

    return Status::success();
  }

  /// Expands a value list returned by osquery into a Row (without the rowid
  /// column)
  Status getRowData(Row& row, const std::string& json_value_array) const {
    row.clear();

    rapidjson::Document document;
    document.Parse(json_value_array);
    if (document.HasParseError() || !document.IsArray()) {
      return Status(1, "Invalid format");
    }

    if (document.Size() != 2U) {
      return Status(1, "Wrong column count");
    }

    row["text"] = document[0].IsNull() ? "" : document[0].GetString();
    row["integer"] =
        std::to_string(document[1].IsNull() ? 0 : document[1].GetInt());

    return Status::success();
  }

 public:
  /// Describes the columns available in the table
  virtual TableColumns columns() const override {
    return {std::make_tuple("text", TEXT_TYPE, ColumnOptions::DEFAULT),
            std::make_tuple("integer", INTEGER_TYPE, ColumnOptions::DEFAULT)};
  }

  /// Generates the rows for osquery
  virtual TableRows generate(QueryContext& request) override {
    std::lock_guard<std::mutex> lock(mutex);

    TableRows result;

    for (const auto& pkey_row_pair : data) {
      auto r = make_table_row();

      for (const auto& column : pkey_row_pair.second) {
        r[column.first] = column.second;
      }

      result.push_back(std::move(r));
    }

    return result;
  }

  /// Callback for INSERT queries
  virtual QueryData insert(QueryContext& context,
                           const PluginRequest& request) override {
    std::lock_guard<std::mutex> lock(mutex);

    // Generate the Row from the json_value_array json
    const auto& json_value_array = request.at("json_value_array");

    Row row;
    auto status = getRowData(row, json_value_array);
    if (!status.ok()) {
      return {{std::make_pair("status", "failure"),
               std::make_pair("message", status.getMessage())}};
    }

    // Make the 'text' column NOT NULL
    if (row["text"].empty()) {
      return {{std::make_pair("status", "constraint")}};
    }

    // Generate a primary key; do this first so that we avoid generating
    // rowids for statements that we then may have to discard!
    auto primary_key = getPrimaryKey(row);
    if (!isPrimaryKeyUnique(primary_key)) {
      return {{std::make_pair("status", "constraint")}};
    }

    // Obtain the new rowid, and add it to our Row
    if (request.at("auto_rowid") == "false") {
      auto new_rowid = generateRowId();
      row["rowid"] = std::to_string(new_rowid);

    } else {
      auto const existing_rowid_exp =
          tryTo<unsigned long long>(request.at("id"), 10);
      if (existing_rowid_exp.isError()) {
        return {
            {std::make_pair("status", "failure"),
             std::make_pair("message", "Invalid rowid defined by osquery")}};
      }

      row["rowid"] = std::to_string(existing_rowid_exp.get());
    }

    // Finally, save the row; also pass the primary key we calculated so that
    // the function doesn't have to compute it again
    status = saveRow(row, primary_key);
    if (!status.ok()) {
      return {{std::make_pair("status", "failure"),
               std::make_pair("message", status.getMessage())}};
    }

    Row result;
    if (request.at("auto_rowid") == "false") {
      result["id"] = row["rowid"];
    }

    result["status"] = "success";
    return {result};
  }

  /// Callback for DELETE queries
  virtual QueryData delete_(QueryContext& context,
                            const PluginRequest& request) override {
    std::lock_guard<std::mutex> lock(mutex);

    const auto& rowid = request.at("id");

    auto primary_key_it = rowid_to_primary_key.find(rowid);
    if (primary_key_it == rowid_to_primary_key.end()) {
      return {{std::make_pair("status", "failure"),
               std::make_pair("message",
                              "The rowid is not mapped to an internal rowid")}};
    }

    const auto& primary_key = primary_key_it->second;

    auto row_it = data.find(primary_key);
    if (row_it == data.end()) {
      return {{std::make_pair("status", "failure"),
               std::make_pair("message", "Row id -> primary key mismatch")}};
    }

    data.erase(row_it);
    rowid_to_primary_key.erase(primary_key_it);

    return {{std::make_pair("status", "success")}};
  }

  // Callback for UPDATE queries
  virtual QueryData update(QueryContext& context,
                           const PluginRequest& request) override {
    std::lock_guard<std::mutex> lock(mutex);

    // Validate the rowid
    const auto& original_rowid = request.at("id");

    auto orig_primary_key_it = rowid_to_primary_key.find(original_rowid);
    if (orig_primary_key_it == rowid_to_primary_key.end()) {
      return {{std::make_pair("status", "failure"),
               std::make_pair("message",
                              "The rowid is not mapped to an internal rowid")}};
    }

    const auto& original_primary_key = orig_primary_key_it->second;

    auto row_it = data.find(original_primary_key);
    if (row_it == data.end()) {
      return {{std::make_pair("status", "failure"),
               std::make_pair("message", "Row id -> primary key mismatch")}};
    }

    // Generate the Row from the json_value_array json
    const auto& json_value_array = request.at("json_value_array");

    Row row;
    auto status = getRowData(row, json_value_array);
    if (!status.ok()) {
      return {{std::make_pair("status", "failure"),
               std::make_pair("message", status.getMessage())}};
    }

    // Make the 'text' column NOT NULL
    if (row["text"].empty()) {
      return {{std::make_pair("status", "constraint")}};
    }

    // Generate a primary key
    auto new_primary_key = getPrimaryKey(row);
    if (!isPrimaryKeyUnique(new_primary_key, original_rowid)) {
      return {{std::make_pair("status", "constraint")}};
    }

    // Add the rowid value to our row
    auto new_rowid_it = request.find("new_id");
    if (new_rowid_it != request.end()) {
      // sqlite has generated the new rowid for us, so we'll discard
      // the one we have
      const auto& new_rowid = new_rowid_it->second;
      row["rowid"] = new_rowid;

    } else {
      // Here we are supposed to keep the rowid we already have
      row["rowid"] = original_rowid;
    }

    // Erase the old row and save the new one
    rowid_to_primary_key.erase(orig_primary_key_it);
    data.erase(row_it);

    status = saveRow(row, new_primary_key);
    if (!status.ok()) {
      return {{std::make_pair("status", "failure"),
               std::make_pair("message", status.getMessage())}};
    }

    return {{std::make_pair("status", "success")}};
  }
};

REGISTER_EXTERNAL(WritableTable, "table", "WritableTable");

int main(int argc, char* argv[]) {
  osquery::Initializer runner(argc, argv, ToolType::EXTENSION);

  auto status = startExtension("WritableTable", "0.0.1");
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    runner.requestShutdown(status.getCode());
  }

  // Finally wait for a signal / interrupt to shutdown.
  runner.waitForShutdown();
  return runner.shutdown(0);
}
