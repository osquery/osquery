/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
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
