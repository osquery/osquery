/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <linux/audit.h>

#include <map>
#include <set>
#include <string>

// All audit messages from LSM are written to audit with this code
const std::set<int> kAppArmorEventSet = {
    AUDIT_AVC,
};

const std::map<int, std::string> kAppArmorRecordLabels = {
    {AUDIT_AVC, "AA"},
};
