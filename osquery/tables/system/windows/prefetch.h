/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/core/core.h>
#include <osquery/core/tables.h>

#include <string>

namespace osquery {
namespace tables {

struct PrefetchHeader {
  int file_size;
  std::string filename;
  std::string prefetch_hash;
};

/**
 * @brief Windows helper function to parse prefetch header data
 *
 * @returns Prefetch header data
 */
PrefetchHeader parseHeader(const std::string& prefetch_data);

/**
 * @brief Windows helper function to parse accessed data in prefetch file
 *
 * @returns Accessed data list
 */
std::vector<std::string> parseAccessedData(const std::string& data,
                                           const std::string& type);

} // namespace tables
} // namespace osquery
