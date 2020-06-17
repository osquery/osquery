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
    return results;
  }

  r["vm_id"] = getAzureKey(doc, "vmId");
  r["location"] = getAzureKey(doc, "location");
  r["name"] = getAzureKey(doc, "name");
  r["offer"] = getAzureKey(doc, "offer");
  r["publisher"] = getAzureKey(doc, "publisher");
  r["sku"] = getAzureKey(doc, "sku");
  r["version"] = getAzureKey(doc, "version");
  r["os_type"] = getAzureKey(doc, "osType");
  r["platform_update_domain"] = getAzureKey(doc, "platformUpdateDomain");
  r["platform_fault_domain"] = getAzureKey(doc, "platformFaultDomain");
  r["vm_size"] = getAzureKey(doc, "vmSize");
  r["subscription_id"] = getAzureKey(doc, "subscriptionId");
  r["resource_group_name"] = getAzureKey(doc, "resourceGroupName");
  r["placement_group_id"] = getAzureKey(doc, "placementGroupId");
  r["vm_scale_set_name"] = getAzureKey(doc, "vmScaleSetName");
  r["zone"] = getAzureKey(doc, "zone");

  results.push_back(r);

  return results;
}
} // namespace tables
} // namespace osquery
