/*
 *  Copyright (c) 2014, Facebook, Inc.
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

#include "osquery/devtools/devtools.h"

namespace osquery {

std::string generateToken(const std::map<std::string, size_t>& lengths,
                          const std::vector<std::string>& columns) {
  std::string output = "+";
  for (const auto& col : columns) {
    if (lengths.count(col) > 0) {
      output += std::string(lengths.at(col) + 2, '-');
    }
    output += "+";
  }

  output += "\n";
  return output;
}

std::string generateHeader(const std::map<std::string, size_t>& lengths,
                           const std::vector<std::string>& columns) {
  std::string output = "|";
  for (const auto& col : columns) {
    output += " " + col;
    if (lengths.count(col) > 0) {
      int buffer_size = lengths.at(col) - utf8StringSize(col) + 1;
      if (buffer_size > 0) {
        output += std::string(buffer_size, ' ');
      } else {
        output += ' ';
      }
    }
    output += "|";
  }
  output += "\n";
  return output;
}

std::string generateRow(const Row& r,
                        const std::map<std::string, size_t>& lengths,
                        const std::vector<std::string>& order) {
  std::string output;
  for (const auto& column : order) {
    if (r.count(column) == 0 || lengths.count(column) == 0) {
      continue;
    }
    // Print a terminator for the previous value or lhs, followed by spaces.

    int buffer_size = lengths.at(column) - utf8StringSize(r.at(column)) + 1;
    if (buffer_size > 0) {
      output += "| " + r.at(column) + std::string(buffer_size, ' ');
    }
  }

  if (output.size() > 0) {
    // Only append if a row was added.
    output += "|\n";
  }

  return output;
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
  for (int i = 0; i < q.size(); ++i) {
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
