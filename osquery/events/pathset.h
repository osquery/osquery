/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <set>
#include <string>
#include <vector>

#include <boost/noncopyable.hpp>
#include <boost/tokenizer.hpp>

#include <osquery/core/core.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/utils/mutex.h>

namespace osquery {

/**
 * @brief multiset based implementation for path search.
 *
 * 'multiset' is used because with patterns we can search for equivalent keys.
 * Since  '/This/Path/is' ~= '/This/Path/%' ~= '/This/Path/%%' (equivalent).
 *
 * multiset is protected by lock. It is threadsafe.
 *
 * PathSet can take any of the two policies -
 * 1. patternedPath - Path can contain pattern '%' and '%%'.
 *                    Path components containing only '%' and '%%' are supported
 *                    e.g. '/This/Path/%'.
 *                    Path components containing partial patterns are not
 *                    supported e.g. '/This/Path/xyz%' ('xyz%' will not be
 *                    treated as pattern).
 */
template <typename PathType>
class PathSet : private boost::noncopyable {
 public:
  void insert(const std::string& str) {
    auto pattern = str;
    replaceGlobWildcards(pattern);
    auto vpath = PathType::createVPath(pattern);

    WriteLock lock(mset_lock_);
    for (auto& path : vpath) {
      paths_.insert(std::move(path));
    }
  }

  bool find(const std::string& str) const {
    auto path = PathType::createPath(str);

    ReadLock lock(mset_lock_);
    if (paths_.find(path) != paths_.end()) {
      return true;
    }
    return false;
  }

  void clear() {
    WriteLock lock(mset_lock_);
    paths_.clear();
  }

  bool empty() const {
    ReadLock lock(mset_lock_);
    return paths_.empty();
  }

 private:
  typedef typename PathType::Path Path;
  typedef typename PathType::Compare Compare;
  std::multiset<Path, Compare> paths_;
  mutable Mutex mset_lock_;
};

class patternedPath {
 public:
  typedef boost::tokenizer<boost::char_separator<char>> tokenizer;
  typedef std::vector<std::string> Path;
  typedef std::vector<Path> VPath;
  struct Compare {
    bool operator()(const Path& lhs, const Path& rhs) const {
      size_t psize = (lhs.size() < rhs.size()) ? lhs.size() : rhs.size();
      unsigned ndx;
      for (ndx = 0; ndx < psize; ++ndx) {
        if (lhs[ndx] == "**" || rhs[ndx] == "**") {
          return false;
        }

        if (lhs[ndx] == "*" || rhs[ndx] == "*") {
          continue;
        }

        int rc = lhs[ndx].compare(rhs[ndx]);

        if (rc > 0) {
          return false;
        }

        if (rc < 0) {
          return true;
        }
      }

      if ((ndx == rhs.size() && rhs[ndx - 1] == "*") ||
          (ndx == lhs.size() && lhs[ndx - 1] == "*")) {
        return false;
      }

      return (lhs.size() < rhs.size());
    }
  };

  static Path createPath(const std::string& str) {
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

  static VPath createVPath(const std::string& str) {
    boost::char_separator<char> sep{"/"};
    tokenizer tokens(str, sep);
    VPath vpath;
    Path path;

    if (str == "/") {
      path.push_back("");
    }

    for (std::string component : tokens) {
      if (component == "**") {
        vpath.push_back(path);
        path.push_back(std::move(component));
        break;
      }
      path.push_back(std::move(component));
    }
    vpath.push_back(std::move(path));
    return vpath;
  }
};

} // namespace osquery
