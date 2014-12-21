/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
 
#pragma once

#include <functional>
#include <map>
#include <mutex>
#include <vector>

#include <boost/noncopyable.hpp>

namespace osquery {

template <class... FuncArgs>
class RegistryTemplate : private boost::noncopyable {
 public:
  typedef std::function<void(FuncArgs...)> Func;
  static const int kDefaultPriority = 100000;

  RegistryTemplate() : alreadyRan_(false) {}

  /**
   * Registers a function to be invoked when 'run()' is called; fails
   * if run() has already been called.  Functions will be run with lowest
   * priority first, with FIFO order on ties.
   *
   * Function isn't allowed to throw, calling registerFunc() from within
   * registered function will cause deadlock.
   */
  bool registerFunc(Func func, int priority = kDefaultPriority) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (alreadyRan_) {
      return false;
    }

    funcMap_[priority].push_back(std::move(func));
    return true;
  }

  /**
   * Runs all functions already registered with registerFunc(), in
   * order from lowest priority to highest (undefined order on ties).
   */
  bool run(FuncArgs... args) noexcept {
    std::lock_guard<std::mutex> guard(mutex_);
    if (alreadyRan_) {
      return false;
    }

    for (const auto& kv : funcMap_) {
      for (const auto& func : kv.second) {
        if (func) {
          func(args...);
        }
      }
    }

    alreadyRan_ = true;
    return true;
  }

 private:
  std::mutex mutex_;
  bool alreadyRan_;

  std::map<int, std::vector<Func> > funcMap_;
};

} // namespace osquery
