// Copyright 2004-present Facebook. All Rights Reserved.

#include <vector>
#include <string>

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

QueryData parseNfsSharesContent(const std::string& content) {
  QueryData results;

  for (const auto& i : split(content, "\n")) {
    auto line = split(i);
    if (line.size() == 0 || boost::starts_with(line[0], "#")) {
      continue;
    }
    std::vector<std::string> line_exports;
    unsigned int readonly = 0;
    int index_of_options = -1;

    for (const auto& iter : line) {
      index_of_options++;
      if (iter[0] == '/') {
        line_exports.push_back(iter);
      } else {
        break;
      }
    }
    // Start looping through starting at the first options
    // (so skip the exports)
    for (std::vector<std::string>::iterator iter =
             line.begin() + index_of_options;
         iter != line.end();
         ++iter) {
      if (iter->compare("-ro") == 0 || iter->compare("-o") == 0) {
        readonly = 1;
      }
    }
    for (const auto& iter : line_exports) {
      Row r;
      r["share"] = iter;
      if (readonly) {
        r["readonly"] = "true";
      } else {
        r["readonly"] = "false";
      }
      std::ostringstream oss;
      std::copy(line.begin() + index_of_options,
                line.end(),
                std::ostream_iterator<std::string>(oss, " "));
      r["options"] = oss.str();
      results.push_back(r);
    }
  }
  return results;
}

QueryData genNfsShares(QueryContext& context) {
  std::string content;
  auto s = osquery::readFile("/etc/exports", content);
  if (s.ok()) {
    return parseNfsSharesContent(content);
  } else {
    VLOG(1) << "Error reading /etc/exports: " << s.toString();
    return {};
  }
}
}
}
