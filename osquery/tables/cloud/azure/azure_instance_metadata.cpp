/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/property_tree/json_parser.hpp>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/utils/azure/azure_util.h"

namespace osquery {
namespace tables {
namespace pt = boost::property_tree;

// Azure VM IDs are unique and don't change on an instance,
// so we can safely cache them.
static std::string kCachedVmId;

QueryData genAzureMetadata(QueryContext& context) {
  QueryData results;
  Row r;

  pt::ptree tree;

  Status s = fetchAzureMetadata(tree);

  if (!s.ok()) {
    TLOG << "Couldn't fetch metadata: " << s.what();
  }

  if (kCachedVmId.empty()) {
    kCachedVmId = tree_get(tree, "vmId");
  }

  r["vm_id"] = kCachedVmId;
  r["location"] = tree_get(tree, "location");
  r["name"] = tree_get(tree, "name");
  r["offer"] = tree_get(tree, "offer");
  r["publisher"] = tree_get(tree, "publisher");
  r["sku"] = tree_get(tree, "sku");
  r["version"] = tree_get(tree, "version");
  r["os_type"] = tree_get(tree, "osType");
  r["platform_update_domain"] = tree_get(tree, "platformUpdateDomain");
  r["platform_fault_domain"] = tree_get(tree, "platformFaultDomain");
  r["vm_size"] = tree_get(tree, "vmSize");
  r["subscription_id"] = tree_get(tree, "subscriptionId");
  r["resource_group_name"] = tree_get(tree, "resourceGroupName");
  r["placement_group_id"] = tree_get(tree, "placementGroupId");
  r["vm_scale_set_name"] = tree_get(tree, "vmScaleSetName");
  r["zone"] = tree_get(tree, "zone");

  results.push_back(r);

  return results;
}
} // namespace tables
} // namespace osquery
