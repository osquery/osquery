/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
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
