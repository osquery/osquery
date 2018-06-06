/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <vector>
#include <string>
#include <unordered_map>

namespace osquery {
using ExtendedAttributes = std::vector<std::pair<std::string, std::string>>;

bool getExtendedAttributes(ExtendedAttributes &attributes, const std::string &path);
bool setExtendedAttributes(const std::string &path, const std::unordered_map<std::string, std::string> &attributes);
}
