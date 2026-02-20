/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <sstream>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry.h>
#include <osquery/sql/sql.h>

#include <osquery/core/plugins/sql.h>

#include <osquery/utils/conversions/split.h>
#include <osquery/utils/info/tool_type.h>

namespace osquery {


CREATE_LAZY_REGISTRY(SQLPlugin, "sql");

SQL::SQL(const std::string& query, bool use_cache) {
  TableColumns table_columns;
  status_ = getQueryColumns(query, table_columns);
  if (status_.ok()) {
    for (auto c : table_columns) {
      columns_.push_back(std::get<0>(c));
    }
    status_ = osquery::query(query, results_, use_cache);
  }
}

const QueryData& SQL::rows() const {
  return results_;
}

QueryData& SQL::rows() {
  return results_;
}

const ColumnNames& SQL::columns() const {
  return columns_;
}

bool SQL::ok() const {
  return status_.ok();
}

const Status& SQL::getStatus() const {
  return status_;
}

std::string SQL::getMessageString() const {
  return status_.toString();
}

// Return the expected byte length of a UTF-8 sequence given its lead byte,
// or 0 if the byte is not a valid UTF-8 lead byte.
static inline size_t utf8SequenceLength(unsigned char lead) {
  if (lead < 0x80) {
    return 1; // ASCII
  } else if (lead < 0xC2) {
    return 0; // continuation byte or overlong 2-byte (0xC0, 0xC1)
  } else if (lead < 0xE0) {
    return 2;
  } else if (lead < 0xF0) {
    return 3;
  } else if (lead < 0xF5) {
    return 4;
  }
  return 0; // 0xF5..0xFF are invalid
}

// Check whether a multi-byte UTF-8 sequence starting at data[i] is valid.
// `len` is the expected sequence length from utf8SequenceLength (2, 3, or 4).
// Returns true only if all continuation bytes are present and the sequence
// is not overlong and does not encode a surrogate half.
static inline bool isValidUtf8Sequence(const std::string& data,
                                       size_t i,
                                       size_t len) {
  if (i + len > data.length()) {
    return false; // not enough bytes remaining
  }

  // All continuation bytes must be 10xxxxxx (0x80..0xBF).
  for (size_t j = 1; j < len; ++j) {
    if (((unsigned char)data[i + j] & 0xC0) != 0x80) {
      return false;
    }
  }

  auto b0 = (unsigned char)data[i];
  auto b1 = (unsigned char)data[i + 1];

  // Reject overlong encodings and surrogate halves (RFC 3629).
  if (len == 3) {
    if (b0 == 0xE0 && b1 < 0xA0) {
      return false; // overlong 3-byte
    }
    if (b0 == 0xED && b1 >= 0xA0) {
      return false; // surrogate half U+D800..U+DFFF
    }
  } else if (len == 4) {
    if (b0 == 0xF0 && b1 < 0x90) {
      return false; // overlong 4-byte
    }
    if (b0 == 0xF4 && b1 >= 0x90) {
      return false; // above U+10FFFF
    }
  }

  return true;
}

static inline void escapeNonPrintableBytes(std::string& data) {
  std::string escaped;
  // clang-format off
  char const hex_chars[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
  };
  // clang-format on

  bool needs_replacement = false;
  for (size_t i = 0; i < data.length(); i++) {
    auto byte = (unsigned char)data[i];

    if (byte < 0x20) {
      // Control characters are always escaped.
      needs_replacement = true;
      escaped += "\\x";
      escaped += hex_chars[byte >> 4];
      escaped += hex_chars[byte & 0x0F];
    } else if (byte < 0x80) {
      // Printable ASCII passes through.
      escaped += data[i];
    } else {
      // Non-ASCII byte: check for valid UTF-8 multi-byte sequence.
      size_t seq_len = utf8SequenceLength(byte);
      if (seq_len >= 2 && isValidUtf8Sequence(data, i, seq_len)) {
        // Valid UTF-8 sequence: copy all bytes through unchanged.
        for (size_t j = 0; j < seq_len; ++j) {
          escaped += data[i + j];
        }
        i += seq_len - 1; // -1 because the for loop increments
      } else {
        // Invalid or unexpected byte: escape it.
        needs_replacement = true;
        escaped += "\\x";
        escaped += hex_chars[byte >> 4];
        escaped += hex_chars[byte & 0x0F];
      }
    }
  }

  // Only replace if any escapes were made.
  if (needs_replacement) {
    data = std::move(escaped);
  }
}

void escapeNonPrintableBytesEx(std::string& data) {
  return escapeNonPrintableBytes(data);
}

QueryData SQL::selectAllFrom(const std::string& table) {
  PluginResponse response;
  Registry::call("table", table, {{"action", "generate"}}, response);
  return response;
}

QueryData SQL::selectAllFrom(const std::string& table,
                             const std::string& column,
                             ConstraintOperator op,
                             const std::string& expr) {
  return selectFrom({}, table, column, op, expr);
}

QueryData SQL::selectFrom(const std::initializer_list<std::string>& columns,
                          const std::string& table,
                          const std::string& column,
                          ConstraintOperator op,
                          const std::string& expr) {
  PluginRequest request = {{"action", "generate"}};
  // Create a fake content, there will be no caching.
  QueryContext ctx;
  ctx.constraints[column].add(Constraint(op, expr));
  if (columns.size() > 0) {
    auto colsUsed = UsedColumns(columns);
    colsUsed.insert(column);
    ctx.colsUsed = colsUsed;
  }
  // We can't set colsUsedBitset here (because we don't know the column
  // indexes). The plugin that handles the request will figure it out from the
  // column names.
  TablePlugin::setRequestFromContext(ctx, request);

  PluginResponse response;
  Registry::call("table", table, request, response);
  response.erase(
      std::remove_if(response.begin(),
                     response.end(),
                     [&ctx, &column](const PluginRequest& row) -> bool {
                       return !ctx.constraints[column].matches(row.at(column));
                     }),
      response.end());
  return response;
}

Status SQLPlugin::call(const PluginRequest& request, PluginResponse& response) {
  response.clear();
  if (request.count("action") == 0) {
    return Status(1, "SQL plugin must include a request action");
  }

  if (request.at("action") == "query") {
    bool use_cache = (request.count("cache") && request.at("cache") == "1");
    return this->query(request.at("query"), response, use_cache);
  } else if (request.at("action") == "columns") {
    TableColumns columns;
    auto status = this->getQueryColumns(request.at("query"), columns);
    // Convert columns to response
    for (const auto& column : columns) {
      response.push_back(
          {{"n", std::get<0>(column)},
           {"t", columnTypeName(std::get<1>(column))},
           {"o", INTEGER(static_cast<size_t>(std::get<2>(column)))}});
    }
    return status;
  } else if (request.at("action") == "attach") {
    // Attach a virtual table name using an optional included definition.
    return this->attach(request.at("table"));
  } else if (request.at("action") == "detach") {
    return this->detach(request.at("table"));
  } else if (request.at("action") == "tables") {
    std::vector<std::string> tables;
    auto status = this->getQueryTables(request.at("query"), tables);
    if (status.ok()) {
      for (const auto& table : tables) {
        response.push_back({{"t", table}});
      }
    }
    return status;
  }
  return Status(1, "Unknown action");
}

Status query(const std::string& q, QueryData& results, bool use_cache) {
  return Registry::call(
      "sql",
      "sql",
      {{"action", "query"}, {"cache", (use_cache) ? "1" : "0"}, {"query", q}},
      results);
}

Status getQueryColumns(const std::string& q, TableColumns& columns) {
  PluginResponse response;
  auto status = Registry::call(
      "sql", "sql", {{"action", "columns"}, {"query", q}}, response);

  // Convert response to columns
  for (const auto& item : response) {
    columns.push_back(make_tuple(
        item.at("n"), columnTypeName(item.at("t")), ColumnOptions::DEFAULT));
  }
  return status;
}

Status mockGetQueryTables(std::string copy_q,
                          std::vector<std::string>& tables) {
  std::transform(copy_q.begin(), copy_q.end(), copy_q.begin(), ::tolower);
  auto offset_from = copy_q.find("from ");
  if (offset_from == std::string::npos) {
    return Status(1);
  }

  auto simple_tables = osquery::split(copy_q.substr(offset_from + 5), ",");
  for (const auto& table : simple_tables) {
    tables.push_back(table);
  }
  return Status(0);
}

Status getQueryTables(const std::string& q, std::vector<std::string>& tables) {
  if (getToolType() == ToolType::TEST) {
    // We 'mock' this functionality for internal tests.
    return mockGetQueryTables(q, tables);
  }

  PluginResponse response;
  auto status = Registry::call(
      "sql", "sql", {{"action", "tables"}, {"query", q}}, response);

  for (const auto& table : response) {
    tables.push_back(table.at("t"));
  }
  return status;
}
}
