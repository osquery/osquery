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

#include <boost/filesystem.hpp>

#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

/// Reads <profiles_dir>/<profile id>/extensions.json for every profile.
void genVSCodeProfileExtensionRows(const std::string& uid,
                                   const boost::filesystem::path& profiles_dir,
                                   const std::string& vscode_edition,
                                   QueryData& results);

} // namespace tables
} // namespace osquery
