/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <memory>

#include <dirent.h>
#include <unistd.h>

namespace osquery {

using UniqueDir = std::unique_ptr<DIR, decltype(&closedir)>;

} // namespace osquery
