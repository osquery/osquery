/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <memory>

#include <dirent.h>
#include <unistd.h>

namespace osquery {
using UniqueDir = std::unique_ptr<DIR, decltype(&closedir)>;
} // namespace osquery
