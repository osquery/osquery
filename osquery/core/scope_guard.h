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

#include <utility>

namespace osquery {

/**
 * The RAII based scoupe guard class.
 *
 * To be sure that resources are always released/removed/closed/verified/stoped
 * in face of multiple return statements from the function.
 *
 * It takes functor object by value during the counstruction. It is going to be
 * called once during the destruction of ScopeGuard object. Besides the case
 * when release method is called manually.
 *
 * There is helper function to create the object of guard.
 * @code{.cpp}
 *   {
 *     auto const manager = ScopeGuard<>::create(
 *       [&file_path]() { fs::remove(file_path); }
 *     );
 *       ...
 *     // it will be removed at the end of scope
 *   }
 * @endcode
 */
template <typename...>
class ScopeGuard final {
 public:
  template <typename FinalRoutineType>
  static inline auto create(FinalRoutineType final_routine) {
    return ScopeGuard<FinalRoutineType>(std::move(final_routine));
  }
};

template <typename FinalRoutineType>
class ScopeGuard<FinalRoutineType> final {
 public:
  explicit ScopeGuard(FinalRoutineType final_routine)
      : final_routine_(std::move(final_routine)) {}

  ~ScopeGuard() {
    final_routine_();
  }

  inline void release() {
    final_routine_();
  }

 private:
  FinalRoutineType final_routine_;
};

} // namespace osquery
