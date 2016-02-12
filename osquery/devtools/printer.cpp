/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <iostream>
#include <sstream>

#include <osquery/core.h>

#include "osquery/core/conversions.h"
#include "osquery/devtools/devtools.h"

namespace osquery {

static std::vector<size_t> kOffset = {0, 0};
static std::string kToken = "|";

std::string generateToken(const std::map<std::string, size_t>& lengths,
                          const std::vector<std::string>& columns) {
  std::string out = "+";
  for (const auto& col : columns) {
    if (lengths.count(col) > 0) {
      if (getenv("ENHANCE") != nullptr) {
        std::string e = "\xF0\x9F\x90\x8C";
        e[2] += kOffset[1];
        e[3] += kOffset[0];
        for (size_t i = 0; i < lengths.at(col) + 2; i++) {
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
        out += std::string(lengths.at(col) + 2, '-');
      }
    }
    out += "+";
  }

  out += "\n";
  return out;
}

std::string generateHeader(const std::map<std::string, size_t>& lengths,
                           const std::vector<std::string>& columns) {
  if (getenv("ENHANCE") != nullptr) {
    kToken = "\xF0\x9F\x91\x8D";
  }
  std::string out = kToken;
  for (const auto& col : columns) {
    out += " " + col;
    if (lengths.count(col) > 0) {
      int buffer_size = lengths.at(col) - utf8StringSize(col) + 1;
      if (buffer_size > 0) {
        out += std::string(buffer_size, ' ');
      } else {
        out += ' ';
      }
    }
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
    if (r.count(column) == 0 || lengths.count(column) == 0) {
      continue;
    }
    // Print a terminator for the previous value or lhs, followed by spaces.

    int buffer_size = lengths.at(column) - utf8StringSize(r.at(column)) + 1;
    if (buffer_size > 0) {
      out += kToken + " " + r.at(column) + std::string(buffer_size, ' ');
    }
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
      row_string.pop_back();
      printf("  %s", row_string.c_str());
      if (i < q.size() - 1) {
        printf(",\n");
      }
    }
  }
  printf("\n]\n");
}

void computeRowLengths(const Row& r,
                       std::map<std::string, size_t>& lengths,
                       bool use_columns) {
  for (const auto& col : r) {
    size_t current = (lengths.count(col.first) > 0) ? lengths.at(col.first) : 0;
    size_t size =
        (use_columns) ? utf8StringSize(col.first) : utf8StringSize(col.second);
    lengths[col.first] = (size > current) ? size : current;
  }
}
}
