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
  void insert(const std::string& str) {
    auto pattern = str;
    replaceGlobWildcards(pattern);
    auto path = PathType::createPath(std::move(pattern));

    WriteLock lock(mset_lock_);
    patterns_.push_back(std::move(path));
  }

  bool find(const std::string& str) const {
    auto path = PathType::createPath(str);

    ReadLock lock(mset_lock_);
    for (auto& pattern : patterns_) {
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
  typedef boost::tokenizer<boost::char_separator<char>> tokenizer;
  typedef std::vector<std::string> Path;
  struct Compare {
    bool compareStrings(boost::string_view vlhs,
                        boost::string_view vrhs) const {
      if (vlhs[0] == '*' && vlhs[vlhs.size() - 1] == '*') {
        vlhs = vlhs.substr(1, vlhs.size() - 2);
        if (vrhs.size() >= vlhs.size() &&
            vrhs.find(vlhs) != boost::string_view::npos) {
          return true;
        }
        return false;
      } else if (vlhs[0] == '*') {
        vlhs = vlhs.substr(1);
        if (vlhs.size() <= vrhs.size()) {
          vrhs = vrhs.substr(vrhs.size() - vlhs.size());
        } else {
          return false;
        }
      } else if (vlhs[vlhs.size() - 1] == '*') {
        vlhs = vlhs.substr(0, vlhs.size() - 1);
        if (vlhs.size() <= vrhs.size()) {
          vrhs = vrhs.substr(0, vlhs.size());
        } else {
          return false;
        }
      }

      return (vlhs.compare(vrhs) == 0);
    }

    bool operator()(const Path& lhs, const Path& rhs) const {
      auto psize = std::min(lhs.size(), rhs.size());
      unsigned ndx;
      for (ndx = 0; ndx < psize; ++ndx) {
        if (lhs[ndx] == "**") {
          return true;
        }

        if (lhs[ndx] == "*") {
          continue;
        }

        // compare with partial patterns
        if (compareStrings(lhs[ndx], rhs[ndx]) == true) {
          continue;
        } else {
          return false;
        }
      }

      return (lhs.size() == rhs.size());
    }
  };

  static Path createPath(std::string str) {
    boost::char_separator<char> sep{"/"};
    tokenizer tokens(str, sep);
    Path path;

    if (str == "/") {
      path.push_back("");
    }

    for (std::string component : tokens) {
      path.push_back(std::move(component));
    }
    return path;
  }
};
} // namespace osquery
