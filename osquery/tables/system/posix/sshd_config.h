/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/tables.h>

#include <string>

namespace osquery {
namespace tables {
namespace sshdconfig {
// parseContent parses the file content from an sshd_config file,
// turning it into table rows.
void parseContent(const std::string& content,
                  const std::string& path,
                  QueryData& rows);

// parseLine parses a line from an sshd_config file into a table
// row and returns it.
Row parseLine(const std::string& line,
              std::string& match,
              const std::string& path);
} // namespace sshdconfig

// genSshdConfig processes the query predicates and returns the table data
QueryData genSshdConfig(QueryContext& context);
} // namespace tables
} // namespace osquery
