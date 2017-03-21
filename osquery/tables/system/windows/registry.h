/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <osquery/core.h>
#include <osquery/tables.h>
namespace osquery {
namespace tables {

// Valid columns/constraints that we use to populate results from registry
const std::map<std::string, std::vector<ConstraintOperator>> kValidConstraints =
    {{"key", {EQUALS, LIKE}}};

/// Microsoft helper function for getting the contents of a registry key
void queryKey(const std::string& keyPath, QueryData& results);

bool validUserConstraintsExist(QueryData& context);

Status expandKeyConstraint(const ConstraintList& constraint, std::set<std::string>& rKeys);

Status expandUserConstraints(QueryContext& context, std::set<std::string>& rKeys);

void maybeWarnLocalUsers(std::set<std::string>& keys);

void explodeRegistryPath(const std::string& path,
                         std::string& rHive,
                         std::string& rKey);
}
}
