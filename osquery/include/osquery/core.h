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

#include <string>

#include <osquery/utils/macros/macros.h>

/// A configuration error is catastrophic and should exit the watcher.
#define EXIT_CATASTROPHIC 78

namespace osquery {

/// Custom literal for size_t.
size_t operator"" _sz(unsigned long long int x);

} // namespace osquery
