/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <cctype>
#include <regex>

#include "osquery/remote/uri.h"

#ifndef UINT16_MAX
#define UINT16_MAX (65535U)
#endif

namespace osquery {

static std::string submatch(const std::smatch& m, int idx) {
  auto& sub = m[idx];
  return std::string(sub.first, sub.second);
}

template <class String>
static inline void toLower(String& s) {
  for (auto& c : s) {
    c = char(tolower(c));
  }
}

Uri::Uri(const std::string& str) : hasAuthority_(false), port_(0) {
  static const std::regex uriRegex(
      "([a-zA-Z][a-zA-Z0-9+.-]*):" // scheme:
      "([^?#]*)" // authority and path
      "(?:\\?([^#]*))?" // ?query
      "(?:#(.*))?"); // #fragment
  static const std::regex authorityAndPathRegex("//([^/]*)(/.*)?");

  std::smatch match;
  if (!std::regex_match(str, match, uriRegex)) {
    throw std::invalid_argument("Invalid URL");
  }

  scheme_ = submatch(match, 1);
  toLower(scheme_);

  std::string authorityAndPath(match[2].first, match[2].second);
  std::smatch authorityAndPathMatch;
  if (!std::regex_match(
          authorityAndPath, authorityAndPathMatch, authorityAndPathRegex)) {
    // Does not start with //, doesn't have authority
    hasAuthority_ = false;
    path_ = authorityAndPath;
  } else {
    static const std::regex authorityRegex(
        "(?:([^@:]*)(?::([^@]*))?@)?" // username, password
        "(\\[[^\\]]*\\]|[^\\[:]*)" // host (IP-literal (e.g. '['+IPv6+']',
                                   // dotted-IPv4, or named host)
        "(?::(\\d*))?"); // port

    auto authority = authorityAndPathMatch[1];
    std::smatch authorityMatch;
    if (!std::regex_match(authority.first,
                          authority.second,
                          authorityMatch,
                          authorityRegex)) {
      throw std::invalid_argument("Invalid URI authority");
    }

    std::string port(authorityMatch[4].first, authorityMatch[4].second);
    if (!port.empty()) {
      int iport = std::stoi(port);
      if (iport < UINT16_MAX && iport >= 0) {
        port_ = static_cast<uint16_t>(iport);
      }
    }

    hasAuthority_ = true;
    username_ = submatch(authorityMatch, 1);
    password_ = submatch(authorityMatch, 2);
    host_ = submatch(authorityMatch, 3);
    path_ = submatch(authorityAndPathMatch, 2);
  }

  query_ = submatch(match, 3);
  fragment_ = submatch(match, 4);
}

std::string Uri::authority() const {
  std::string result;

  // Port is 5 characters max and we have up to 3 delimiters.
  result.reserve(host().size() + username().size() + password().size() + 8);

  if (!username().empty() || !password().empty()) {
    result.append(username());

    if (!password().empty()) {
      result.push_back(':');
      result.append(password());
    }

    result.push_back('@');
  }

  result.append(host());

  if (port() != 0) {
    result.push_back(':');
    result.append(std::to_string(port()));
  }

  return result;
}

std::string Uri::hostname() const {
  if (host_.size() > 0 && host_[0] == '[') {
    return host_.substr(1, host_.size() - 2);
  }
  return host_;
}

const std::vector<std::pair<std::string, std::string>>& Uri::getQueryParams() {
  if (!query_.empty() && queryParams_.empty()) {
    // Parse query string
    static const std::regex queryParamRegex(
        "(^|&)" /*start of query or start of parameter "&"*/
        "([^=&]*)=?" /*parameter name and "=" if value is expected*/
        "([^=&]*)" /*parameter value*/
        "(?=(&|$))" /*forward reference, next should be end of query or
                      start of next parameter*/);
    std::cregex_iterator paramBeginItr(
        query_.data(), query_.data() + query_.size(), queryParamRegex);
    std::cregex_iterator paramEndItr;
    for (auto itr = paramBeginItr; itr != paramEndItr; itr++) {
      if (itr->length(2) == 0) {
        // key is empty, ignore it
        continue;
      }
      queryParams_.emplace_back(
          std::string((*itr)[2].first, (*itr)[2].second), // parameter name
          std::string((*itr)[3].first, (*itr)[3].second) // parameter value
      );
    }
  }
  return queryParams_;
}

} // namespace osquery
