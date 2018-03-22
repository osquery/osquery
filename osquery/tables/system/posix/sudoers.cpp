/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <locale>
#include <vector>

#include <boost/algorithm/string/trim.hpp>

#include <osquery/filesystem.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

namespace osquery {
namespace tables {

#if !defined(FREEBSD)
const std::string kSudoFile{"/etc/sudoers"};
#else
const std::string kSudoFile{"/usr/local/etc/sudoers"};
#endif

QueryData genSudoers(QueryContext& context) {
  QueryData results;

  if (!isReadable(kSudoFile).ok()) {
    return results;
  }

  std::string contents;
  if (!forensicReadFile(kSudoFile, contents).ok()) {
    return results;
  }

  auto lines = split(contents, "\n");
  std::vector<std::string> valid_lines;

  for (auto& line : lines) {
    boost::trim(line);

    // Only add lines that are not comments or blank.
    if (line.size() > 0 && line.at(0) != '#') {
      valid_lines.push_back(line);
    }
  }

  for (const auto& line : valid_lines) {
    Row r;
    auto cols = split(line);
    r["header"] = cols.at(0);

    cols.erase(cols.begin());
    r["rule_details"] = join(cols, " ");

    results.push_back(r);
  }

  return results;
}
}
}
