/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <boost/property_tree/ptree.hpp>
#include <osquery/status.h>

namespace pt = boost::property_tree;

namespace osquery {

// 2018-02-01 is supported across all Azure regions, according to MS.
const std::string kAzureMetadataEndpoint =
    "http://169.254.169.254/metadata/instance/compute?api-version=2018-02-01";

std::string tree_get(pt::ptree& tree, const std::string key);

Status fetchAzureMetadata(pt::ptree& tree);

} // namespace osquery
