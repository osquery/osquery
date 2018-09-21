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

namespace osquery {

/**
 * @brief An abstract similar to boost's noncopyable that defines moves.
 *
 * By defining protected move constructors we allow the children to assign
 * their's as default.
 */
class only_movable {
 protected:
  /// Boilerplate self default constructor.
  only_movable() = default;

  /// Boilerplate self destructor.
  ~only_movable() = default;

  /// Boilerplate move constructor.
  only_movable(only_movable&&) noexcept = default;

  /// Boilerplate move assignment.
  only_movable& operator=(only_movable&&) = default;

 public:
  /// Important, a private copy constructor prevents copying.
  only_movable(const only_movable&) = delete;

  /// Important, a private copy assignment constructor prevents copying.
  only_movable& operator=(const only_movable&) = delete;
};

} // namespace osquery
