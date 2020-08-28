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
namespace schemer {

enum class JsonError {
  Syntax = 1,
  TypeMismatch = 2,
  MissedKey = 3,
  IncorrectFormat = 4,
};

} // namespace schemer
} // namespace osquery
