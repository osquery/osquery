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
 * Scoupe guards
 * To be sure that resources are always released/closed/verified in face of
 * multiple return statements from the function
 */
namespace scope_guard {

template <typename ValueType, typename FinalRoutineType>
auto value(ValueType resource, FinalRoutineType final_routine) {
  auto deleter = [final_routine = std::move(final_routine)](ValueType* res) {
    final_routine(*res);
    delete res;
  };
  return std::unique_ptr<ValueType, decltype(deleter)>(
      new ValueType{std::move(resource)}, std::move(deleter));
}

template <typename ValueType, typename FinalRoutineType>
auto cref(ValueType const& resourceRef, FinalRoutineType final_routine) {
  auto deleter = [final_routine = std::move(final_routine)](auto res) {
    final_routine(res->get());
    delete res;
  };
  using ValueConstRefWrapperType = std::reference_wrapper<ValueType const>;
  return std::unique_ptr<ValueConstRefWrapperType, decltype(deleter)>(
      new ValueConstRefWrapperType{resourceRef}, std::move(deleter));
}

namespace impl {

template<
  typename FinalRoutineType
>
class Guard final {
public:
  explicit Guard(FinalRoutineType final_routine)
    : final_routine_(std::move(final_routine))
  {
  }

  ~Guard() {
    final_routine_();
  }

private:
  FinalRoutineType final_routine_;
};

} // namespace impl

template <typename FinalRoutineType>
auto atExit(FinalRoutineType final_routine) {
  return impl::Guard<FinalRoutineType>(std::move(final_routine));
}

} // namespace scope_guard

} // namespace osquery
