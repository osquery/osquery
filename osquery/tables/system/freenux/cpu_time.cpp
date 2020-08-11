/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/utils/conversions/split.h>

namespace osquery {
namespace tables {

const std::string kProcStat = "/proc/stat";

std::vector<std::string> procFromFile(const std::string& path) {
  if (!isReadable(path).ok()) {
    return {};
  }

  std::string content;
  if (!readFile(path, content).ok()) {
    return {};
  }

  auto lines = split(content, "\n");
  std::vector<std::string> proc_lines;
  for (auto& line : lines) {
    boost::trim(line);
    if (boost::starts_with(line, "cpu")) {
      proc_lines.push_back(line);
    }
  }

  // Remove first cpu line which doesn't give specific core information.
  if (proc_lines.size() > 0 && proc_lines.front().size() >= 4 &&
      proc_lines.front().substr(0, 4).compare("cpu ") == 0) {
    proc_lines.erase(proc_lines.begin());
  }

  return proc_lines;
}

static void genCpuTimeLine(const std::string& line, QueryData& results) {
  auto words = osquery::split(line, " ");
  auto num_words = words.size();

  if (num_words < 8) {
    // This probably means there's an error in the /proc/stat file.
    return;
  }

  if (words[0].size() > 3 && words[0].substr(0, 3).compare("cpu") == 0) {
    words[0].erase(0, 3);
  } else {
    // First column must start with "cpu" followed by a number
    return;
  }
  Row r;
  r["core"] = words[0];
  r["user"] = words[1];
  r["nice"] = words[2];
  r["system"] = words[3];
  r["idle"] = words[4];
  r["iowait"] = words[5];
  r["irq"] = words[6];
  r["softirq"] = words[7];
  r["steal"] = num_words > 8 ? words[8] : "0";
  r["guest"] = num_words > 9 ? words[9] : "0";
  r["guest_nice"] = num_words > 10 ? words[10] : "0";

  results.push_back(r);
}

QueryData genCpuTime(QueryContext& context) {
  QueryData results;

  auto proc_lines = procFromFile(kProcStat);
  for (const auto& line : proc_lines) {
    genCpuTimeLine(line, results);
  }

  return results;
}
}
}
