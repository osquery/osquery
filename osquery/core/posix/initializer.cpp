/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
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
