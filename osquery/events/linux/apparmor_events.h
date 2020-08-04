/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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
