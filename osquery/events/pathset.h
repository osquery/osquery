/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <mutex>
#include <string>
#include <vector>

#include <boost/noncopyable.hpp>
#include <boost/tokenizer.hpp>
#include <boost/utility/string_view.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>

namespace osquery {

/**
 * @brief Vector based implemention for path search.
 *
 * PathSet applies the following policy -
 * patternedPath -    Path can contain pattern '%' and '%%'.
 *                    Path components containing partial patterns are also
 *                    supported e.g. '/This/Path/xyz%' or '/This/Path/%xyz'
 *                    or '/This/Path/%xyz%' but '/This/Path/xy%z'
 *                    is not supported i.e. 'xy%z' is considered as normal
 *                    string.
 *
 */
template <typename PathType>
class PathSet : private boost::noncopyable {
 public:
  void insert(std::string pattern) {
    replaceGlobWildcards(pattern);
    auto path = PathType::createPath(std::move(pattern));

    WriteLock lock(mset_lock_);
    patterns_.push_back(std::move(path));
  }

  bool find(const std::string& str) const {
    auto path = PathType::createPath(str);

    ReadLock lock(mset_lock_);
    for (const auto& pattern : patterns_) {
      if (compare(pattern, path)) {
        return true;
      }
    }
    return false;
  }

  void clear() {
    WriteLock lock(mset_lock_);
    patterns_.clear();
  }

  bool empty() const {
    ReadLock lock(mset_lock_);
    return patterns_.empty();
  }

 private:
  typedef typename PathType::Path Path;
  typedef typename PathType::Compare Compare;
  std::vector<Path> patterns_;
  mutable Mutex mset_lock_;
  Compare compare;
};

class patternedPath {
 public:
  typedef std::vector<std::string> Path;
  struct Compare {
    bool compareStrings(boost::string_view pattern,
                        boost::string_view str) const {
      if (pattern[0] == '*' && pattern[pattern.size() - 1] == '*') {
        pattern = pattern.substr(1, pattern.size() - 2);
        if (str.size() >= pattern.size() &&
            str.find(pattern) != boost::string_view::npos) {
          return true;
        }
        return false;
      } else if (pattern[0] == '*') {
        pattern = pattern.substr(1);
        if (pattern.size() <= str.size()) {
          str = str.substr(str.size() - pattern.size());
        } else {
          return false;
        }
      } else if (pattern[pattern.size() - 1] == '*') {
        pattern = pattern.substr(0, pattern.size() - 1);
        if (pattern.size() <= str.size()) {
          str = str.substr(0, pattern.size());
        } else {
          return false;
        }
      }

      return (pattern == str);
    }

    bool operator()(const Path& pattern, const Path& str) const {
      auto psize = std::min(pattern.size(), str.size());
      for (size_t ndx = 0; ndx < psize; ++ndx) {
        if (pattern[ndx] == "**") {
          return true;
        }

        if (pattern[ndx] == "*") {
          continue;
        }

        // compare with partial patterns
        if (compareStrings(pattern[ndx], str[ndx]) == true) {
          continue;
        } else {
          return false;
        }
      }

      return (pattern.size() == str.size());
    }
  };

  static Path createPath(std::string str) {
    boost::char_separator<char> sep{"/"};
    typedef boost::tokenizer<boost::char_separator<char>> tokenizer;
    tokenizer tokens(str, sep);
    Path path;

    if (str == "/") {
      path.push_back("/");
    }

    for (std::string component : tokens) {
      path.push_back(std::move(component));
    }
    return path;
  }
};
} // namespace osquery
