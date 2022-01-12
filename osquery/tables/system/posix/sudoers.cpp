/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <locale>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <boost/filesystem/path.hpp>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/split.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

#if !defined(FREEBSD)
const std::string kSudoFile = "/etc/sudoers";
#else
const std::string kSudoFile = "/usr/local/etc/sudoers";
#endif

const std::string kSudoWhitespaceChars = "\t\v ";

// sudoers(5): No more than 128 files are allowed to be nested.
static const unsigned int kMaxNest = 128;

void genSudoersFile(const std::string& filename,
                    unsigned int level,
                    QueryData& results) {
  if (level > kMaxNest) {
    TLOG << "sudoers file recursion maximum reached";
    return;
  }

  bool is_long_line = false;
  std::string contents;
  if (!forensicReadFile(filename, contents).ok()) {
    TLOG << "couldn't read sudoers file: " << filename;
    return;
  }

  auto lines = split(contents, "\n");
  for (auto& line : lines) {
    // sudoers uses EBNF for grammar. But for our purposes, we don't need a full
    // parsing. We're just conveying simplified information. We can just split
    // it into the leading token and the trailing token.

    boost::trim_if(line, boost::is_any_of(kSudoWhitespaceChars));

    if (line.empty()) {
      continue;
    }

    // if last line contains a backslash as the last character,
    // treat current line as part of previous line and
    // append it to appropriate column.
    if (is_long_line) {
      is_long_line = (line.back() == '\\');
      auto& last_line = results.back();
      if (last_line["rule_details"].empty()) {
        last_line["header"].pop_back();
      } else {
        last_line["rule_details"].pop_back();
      }
      last_line["rule_details"].append(line);
      continue;
    }

    // Find the rule header
    auto header_len = line.find_first_of(kSudoWhitespaceChars);
    auto header = line.substr(0, header_len);
    boost::trim_if(header, boost::is_any_of(kSudoWhitespaceChars));

    // We frequently check if these are include headers. Do it once here.
    auto is_include = (header == "#include" || header == "@include");
    auto is_includedir = (header == "#includedir" || header == "@includedir");

    // skip comments.
    if (line.at(0) == '#' && !is_include && !is_includedir) {
      continue;
    }

    // Find the next field. Instead of skipping the whitespace, we
    // include it, and then trim it.
    auto rule_details =
        (header_len < line.size()) ? line.substr(header_len) : "";
    boost::trim_if(rule_details, boost::is_any_of(kSudoWhitespaceChars));

    // If an include is _missing_ the target to include, treat it like a
    // comment.
    if (rule_details.empty() && (is_include || is_includedir)) {
      continue;
    }

    // Check if a blackslash is the last character on this line.
    if (!is_include && !is_includedir && line.back() == '\\') {
      is_long_line = true;
    }

    Row r;

    r["header"] = header;
    r["source"] = filename;
    r["rule_details"] = rule_details;
    results.push_back(std::move(r));

    if (is_includedir) {
      // support both relative and full paths
      if (rule_details.at(0) != '/') {
        auto path = fs::path(filename).parent_path() / rule_details;
        rule_details = path.string();
      }

      std::vector<std::string> inc_files;
      if (!listFilesInDirectory(rule_details, inc_files).ok()) {
        TLOG << "Could not list includedir: " << rule_details;
        continue;
      }

      for (const auto& inc_file : inc_files) {
        std::string inc_basename = fs::path(inc_file).filename().string();

        // Per sudoers(5): Any files in the included directory that
        // contain a '.' or end with '~' are ignored.
        if (inc_basename.empty() ||
            inc_basename.find('.') != std::string::npos ||
            inc_basename.back() == '~') {
          continue;
        }

        genSudoersFile(inc_file, ++level, results);
      }
    }
    if (is_include) {
      // support both relative and full paths
      if (rule_details.at(0) != '/') {
        auto path = fs::path(filename).parent_path() / rule_details;
        rule_details = path.string();
      }

      genSudoersFile(rule_details, ++level, results);
    }
  }
}

QueryData genSudoers(QueryContext& context) {
  QueryData results;

  if (!isReadable(kSudoFile).ok()) {
    return results;
  }

  genSudoersFile(kSudoFile, 1, results);

  return results;
}
} // namespace tables
} // namespace osquery
