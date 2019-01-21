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

/// Safer way to do realpath
const std::string canonicalize_file_name(const char* name);

}
