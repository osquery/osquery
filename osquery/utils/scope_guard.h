/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <utility>

namespace osquery {

namespace scope_guard {
/**
 * The RAII based scope guard class.
 *
 * To be sure that resources are always released/removed/closed/verified/stoped
 * in face of multiple return statements from the function.
 *
 * It takes functor object by value during the construction. It is going to be
 * called once and only once during the destruction of Guard object.
 *
 * There is helper function to create the object of guard.
 * @code{.cpp}
 *   {
 *     auto const manager = scope_guard::create(
 *       [&file_path]() { fs::remove(file_path); }
 *     );
 *       ...
 *     // it will be removed at the end of scope
 *   }
 * @endcode
 */
template <typename FinalRoutineType>
class Guard final {
 public:
  explicit Guard(FinalRoutineType final_routine)
      : final_routine_(std::move(final_routine)) {}

  ~Guard() {
    final_routine_();
  }

 private:
  FinalRoutineType final_routine_;
};

template <typename FinalRoutineType>
inline auto create(FinalRoutineType&& final_routine) {
  return Guard<FinalRoutineType>(std::forward<FinalRoutineType>(final_routine));
}

} // namespace scope_guard

} // namespace osquery
