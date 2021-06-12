/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/utils/system/system.h>

#include <string>
#include <vector>

namespace osquery {

struct JumplistData {
  std::string lnk_data;
  int entry;
  int interaction_count;
};
/**
 * @brief Windows helper function for OLE CF Jumplist data
 *
 * @returns A vector of Windows shortcut data and jumplist metadata
 */
std::vector<JumplistData> parseOlecf(const std::vector<char>& olecf_data);

} // namespace osquery
