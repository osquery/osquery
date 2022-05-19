/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>

#include <boost/filesystem/path.hpp>

namespace osquery {

extern const std::string kTopLevelMockFolderName;

// generate a small directory structure for testing
boost::filesystem::path createMockFileStructure();

} // namespace
