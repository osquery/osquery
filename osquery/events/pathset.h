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
#include <set>
#include <string>
#include <vector>
#include <algorithm>

#include <boost/noncopyable.hpp>
#include <boost/tokenizer.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>

namespace osquery {

/**
 * @brief multiset based implementation for path search.
 *
 * 'multiset' is used because with patterns we can serach for equivalent keys.
 * Since  '/This/Path/is' ~= '/This/Path/%' ~= '/This/Path/%%' (equivalent).
 *
 * multiset is protected by lock. It is threadsafe.
 *
 * PathSet can take any of the two policies -
 * 1. PatternedPath - Path can contain pattern '%' and '%%'.
 *                    Path components containing only '%' and '%%' are supported
 *                    e.g. '/This/Path/%'.
 *                    Path components containing partial patterns are not
 *                    supported e.g. '/This/Path/xyz%' ('xyz%' will not be
 *                    treated as pattern).
 *
 * 2. ResolvedPath - path is resolved before being inserted into set.
 *                   But path can match recursively.
 *
 */
template <typename PathType>
class PathSet : private boost::noncopyable {
 public:
  void insert(std::string pattern) {
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
    return (paths_.find(path) != paths_.end());
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

class PatternedPath {
 public:
  typedef boost::tokenizer<boost::char_separator<char>> tokenizer;
  typedef std::vector<std::string> Path;
  typedef std::vector<Path> VPath;
  struct Compare {
    bool operator()(const Path& lhs, const Path& rhs) const {
      size_t psize = std::min(lhs.size(), rhs.size());
      size_t ndx;
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
        }else if (rc < 0) {
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

class ResolvedPath {
 public:
  struct Path {
    Path(const std::string& str, bool r = false) : path(str), recursive(r) {}
    const std::string path;
    bool recursive{false};
  };
  typedef std::vector<Path> VPath;

  struct Compare {
    bool operator()(const Path& lhs, const Path& rhs) const {
      size_t size = (lhs.path.size() < rhs.path.size()) ? lhs.path.size()
                                                        : rhs.path.size();

      int rc = lhs.path.compare(0, size, rhs.path, 0, size);

      if (rc > 0) {
        return false;
      }

      if (rc < 0) {
        return true;
      }

      if ((size < rhs.path.size() && lhs.recursive) ||
          (size < lhs.path.size() && rhs.recursive)) {
        return false;
      }

      return (lhs.path.size() < rhs.path.size());
    }
  };

  static Path createPath(const std::string& str) {
    return Path(str);
  }

  static VPath createVPath(const std::string& str) {
    bool recursive = false;
    std::string pattern(str);
    if (pattern.find("**") != std::string::npos) {
      recursive = true;
      pattern = pattern.substr(0, pattern.find("**"));
    }

    std::vector<std::string> paths;
    resolveFilePattern(pattern, paths);

    VPath vpath;
    for (const auto& path : paths) {
      vpath.push_back(Path(path, recursive));
    }
    return vpath;
  }
};

} // namespace osquery
