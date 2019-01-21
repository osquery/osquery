/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

#pragma once

#include <string>

namespace osquery {

/// Returns a C++ string explaining the errnum
std::string platformStrerr(int errnum);

}
