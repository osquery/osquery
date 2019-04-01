/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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
