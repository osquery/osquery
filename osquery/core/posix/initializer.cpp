/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/system.h>

namespace osquery {

void Initializer::platformSetup() {
  /* No platform-specific logic is needed on POSIX. */
}

void Initializer::platformTeardown() {
  /* No platform-specific logic is needed on POSIX. */
}
} // namespace osquery
