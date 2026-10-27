/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/posix/sshd_config.h>
#include <osquery/utils/conversions/split.h>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/trim.hpp>

namespace osquery {
namespace tables {
namespace sshdconfig {

void parseContent(const std::string& content,
                  const std::string& path,
                  QueryData& rows) {
  std::string match;

  for (const std::string& line : split(content, "\n")) {
    if (line.empty() || line.front() == '#') {
      continue;
    }

    rows.push_back(parseLine(line, match, path));
  }
}

namespace {

// Truncate a line at the start of an inline comment. A '#' begins a comment
// only when it is outside double quotes and at a token boundary (start of line
// or preceded by whitespace); a '#' adjoining non-whitespace (e.g. "foo#bar")
// is literal, matching sshd. sshd cuts a quoted value short at an interior '#';
// we deliberately treat '#' inside double quotes as literal instead.
std::string stripInlineComment(const std::string& line) {
  bool in_quotes = false;
  for (size_t i = 0; i < line.size(); ++i) {
    const char c = line[i];
    if (c == '"') {
      in_quotes = !in_quotes;
    } else if (c == '#' && !in_quotes &&
               (i == 0 || line[i - 1] == ' ' || line[i - 1] == '\t')) {
      return line.substr(0, i);
    }
  }
  return line;
}

} // namespace

Row parseLine(const std::string& line,
              std::string& match,
              const std::string& path) {
  std::string stripped = stripInlineComment(line);
  boost::algorithm::trim(stripped);

  // Separate the keyword from its argument. sshd accepts whitespace and/or a
  // single optional '=' as the separator ("Key val", "Key=val", "Key = val").
  std::string keyword = stripped;
  std::string argument;
  const size_t keyword_end = stripped.find_first_of(" \t=");
  if (keyword_end != std::string::npos) {
    keyword = stripped.substr(0, keyword_end);
    size_t pos = stripped.find_first_not_of(" \t", keyword_end);
    if (pos != std::string::npos && stripped[pos] == '=') {
      pos = stripped.find_first_not_of(" \t", pos + 1);
    }
    if (pos != std::string::npos) {
      argument = stripped.substr(pos);
      boost::algorithm::trim_right(argument);
    }
  }

  // Match and Subsystem carry a leading selector ("Match User ...",
  // "Subsystem sftp ...") that we fold into the keyword as "Match/User" or
  // "Subsystem/sftp", case preserved. The remaining argument is kept verbatim
  // (internal whitespace and quotes intact) rather than split and rejoined.
  if (boost::algorithm::iequals(keyword, "match") ||
      boost::algorithm::iequals(keyword, "subsystem")) {
    if (boost::algorithm::iequals(keyword, "match")) {
      match = argument;
    }
    if (!argument.empty()) {
      const size_t sep = argument.find_first_of(" \t");
      if (sep == std::string::npos) {
        keyword += "/" + argument;
        argument.clear();
      } else {
        keyword += "/" + argument.substr(0, sep);
        argument = argument.substr(sep);
        boost::algorithm::trim(argument);
      }
    }
  }

  return Row({{"keyword", keyword},
              {"argument", argument},
              {"match", match},
              {"path", path}});
}
} // namespace sshdconfig

QueryData genSshdConfig(QueryContext& context) {
  QueryData rows;

  std::set<std::string> paths = context.constraints["path"].getAll(EQUALS);
  for (const std::string& path : paths) {
    std::string content;
    if (!readFile(path, content).ok()) {
      TLOG << "unable to read file: " << path;

      continue;
    }

    sshdconfig::parseContent(content, path, rows);
  }

  return rows;
}

} // namespace tables
} // namespace osquery
