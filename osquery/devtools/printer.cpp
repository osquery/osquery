/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iostream>
#include <sstream>

#include <osquery/core/core.h>
#include <osquery/core/flags.h>
#include <osquery/devtools/devtools.h>
#include <osquery/process/process.h>
#include <osquery/utils/chars.h>
#include <osquery/utils/map_take.h>
#include <osquery/utils/system/env.h>

namespace osquery {

DECLARE_string(nullvalue);

static std::vector<char> kOffset = {0, 0};
static std::string kToken = "|";

std::string generateToken(const std::map<std::string, size_t>& lengths,
                          const std::vector<std::string>& columns) {
  std::string out = "+";
  for (const auto& col : columns) {
    size_t size = tryTakeCopy(lengths, col).takeOr(col.size()) + 2;
    if (getEnvVar("ENHANCE").is_initialized()) {
      std::string e = "\xF0\x9F\x90\x8C";
      e[2] += kOffset[1];
      e[3] += kOffset[0];
      for (size_t i = 0; i < size; i++) {
        e[3] = '\x8c' + kOffset[0]++;
        if (e[3] == '\xbf') {
          e[3] = '\x80';
          kOffset[1] = (kOffset[1] > 3 && kOffset[1] < 8) ? 9 : kOffset[1];
          e[2] = '\x90' + ++kOffset[1];
          kOffset[0] = 0;
        }
        if (kOffset[1] == ('\x97' - '\x8d')) {
          kOffset = {0, 0};
        }
        out += e.c_str();
      }
    } else {
      out += std::string(size, '-');
    }
    out += "+";
  }

  out += "\n";
  return out;
}

std::string generateHeader(const std::map<std::string, size_t>& lengths,
                           const std::vector<std::string>& columns) {
  if (getEnvVar("ENHANCE").is_initialized()) {
    kToken = "\xF0\x9F\x91\x8D";
  }
  std::string out = kToken;
  for (const auto& col : columns) {
    out += " " + col;
    if (lengths.count(col) > 0) {
      int buffer_size = static_cast<int>(lengths.at(col) - utf8StringSize(col));
      if (buffer_size > 0) {
        out += std::string(buffer_size, ' ');
      }
    }
    out += ' ';
    out += kToken;
  }
  out += "\n";
  return out;
}

std::string generateRow(const Row& r,
                        const std::map<std::string, size_t>& lengths,
                        const std::vector<std::string>& order) {
  std::string out;
  for (const auto& column : order) {
    size_t size = 0;

    // Print a terminator for the previous value or lhs, followed by spaces.
    out += kToken + ' ';
    if (r.count(column) == 0 || lengths.count(column) == 0) {
      size = column.size() - utf8StringSize(FLAGS_nullvalue);
      out += FLAGS_nullvalue;
    } else {
      int buffer_size =
          static_cast<int>(lengths.at(column) - utf8StringSize(r.at(column)));
      if (buffer_size >= 0) {
        size = static_cast<size_t>(buffer_size);
        out += r.at(column);
      }
    }
    out += std::string(size + 1, ' ');
  }

  if (out.size() > 0) {
    // Only append if a row was added.
    out += kToken + "\n";
  }

  return out;
}

void prettyPrint(const QueryData& results,
                 const std::vector<std::string>& columns,
                 std::map<std::string, size_t>& lengths) {
  if (results.size() == 0) {
    return;
  }

  // Call a final compute using the column names as minimum lengths.
  computeRowLengths(results.front(), lengths, true);

  // Output a nice header wrapping the column names.
  auto separator = generateToken(lengths, columns);
  auto header = separator + generateHeader(lengths, columns) + separator;
  printf("%s", header.c_str());

  // Iterate each row and pretty print.
  for (const auto& row : results) {
    printf("%s", generateRow(row, lengths, columns).c_str());
  }
  printf("%s", separator.c_str());
}

void jsonPrint(const QueryData& q) {
  printf("[\n");
  for (size_t i = 0; i < q.size(); ++i) {
    std::string row_string;

    if (serializeRowJSON(q[i], row_string).ok()) {
      printf("  %s", row_string.c_str());
      if (i < q.size() - 1) {
        printf(",\n");
      }
    }
  }
  printf("\n]\n");
}

void jsonPrettyPrint(const QueryData& q) {
  auto doc = JSON::newArray();
  for (const auto& row : q) {
    auto row_json = doc.getObject();
    if (serializeRow(row, ColumnNames{}, doc, row_json)) {
      doc.push(row_json);
    }
  }
  std::string doc_string;
  doc.toPrettyString(doc_string);
  printf("%s\n", doc_string.c_str());
}

void computeRowLengths(const Row& r,
                       std::map<std::string, size_t>& lengths,
                       bool use_columns) {
  for (const auto& col : r) {
    size_t current = tryTakeCopy(lengths, col.first).takeOr(std::size_t{0});
    size_t size =
        (use_columns) ? utf8StringSize(col.first) : utf8StringSize(col.second);
    lengths[col.first] = (size > current) ? size : current;
  }
}
} // namespace osquery
