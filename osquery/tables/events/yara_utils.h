
/*
 *  Copyright (c) 2015, Wesley Shields
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <map>
#include <string>
#include <vector>

#include <yara.h>

#include <osquery/status.h>

namespace osquery {
namespace tables {

/**
 * Common initilization function. Compile vector of rule_files and save result
 * in rules map, indexed by category.
 */
Status handleRuleFiles(std::string category,
                       std::vector<std::string> rule_files,
                       std::map<std::string, YR_RULES *> *rules);

/**
 * This is the callback for YARA.
 */
int YARACallback(int message, void *message_data, void *user_data);

}
}
