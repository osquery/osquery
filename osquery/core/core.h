/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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
