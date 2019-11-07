/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/utils/azure/azure_util.h>

namespace osquery {
namespace tables {

QueryData genAzureMetadata(QueryContext& context) {
  QueryData results;
  Row r;

  JSON doc;

  Status s = fetchAzureMetadata(doc);

  if (!s.ok()) {
    TLOG << "Couldn't fetch metadata: " << s.what();
  }

  r["vm_id"] = tree_get(doc, "vmId");
  r["location"] = tree_get(doc, "location");
  r["name"] = tree_get(doc, "name");
  r["offer"] = tree_get(doc, "offer");
  r["publisher"] = tree_get(doc, "publisher");
  r["sku"] = tree_get(doc, "sku");
  r["version"] = tree_get(doc, "version");
  r["os_type"] = tree_get(doc, "osType");
  r["platform_update_domain"] = tree_get(doc, "platformUpdateDomain");
  r["platform_fault_domain"] = tree_get(doc, "platformFaultDomain");
  r["vm_size"] = tree_get(doc, "vmSize");
  r["subscription_id"] = tree_get(doc, "subscriptionId");
  r["resource_group_name"] = tree_get(doc, "resourceGroupName");
  r["placement_group_id"] = tree_get(doc, "placementGroupId");
  r["vm_scale_set_name"] = tree_get(doc, "vmScaleSetName");
  r["zone"] = tree_get(doc, "zone");

  results.push_back(r);

  return results;
}
} // namespace tables
} // namespace osquery
