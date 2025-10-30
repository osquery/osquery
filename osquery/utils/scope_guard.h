/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <utility>

#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#endif

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

#ifdef __APPLE__
/**
 * Helper function to create a scope guard that releases a CoreFoundation
 * object.
 *
 * @param cf_object Reference to a CFTypeRef that will be released
 * @return A scope guard that will call CFRelease on the object if it's not null
 *
 * @code{.cpp}
 *   auto node = ODNodeCreateWithNodeType(...);
 *   const auto node_guard = scope_guard::CFRelease(node);
 *   // node will be automatically released at the end of scope
 * @endcode
 */
template <typename CFTypeRef>
inline auto CFRelease(CFTypeRef& cf_object) {
  return create([&cf_object]() {
    if (cf_object != nullptr) {
      ::CFRelease(cf_object);
    }
  });
}
#endif

} // namespace scope_guard

} // namespace osquery
