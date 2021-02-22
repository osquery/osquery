/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */
// Keep this included first (See #6507).
#include <osquery/remote/http_client.h>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/json/json.h>
#include <osquery/utils/ycloud/ycloud_util.h>

namespace osquery {
namespace tables {

const std::string kMetadataEndpointColumn = "metadata_endpoint";

QueryData genYCloudMetadata(QueryContext& context) {
  QueryData results;
  std::string defaultEndpoint =
      "http://" + osquery::http::kInstanceMetadataAuthority;

  std::vector<std::string> endpoints;

  if (context.hasConstraint(kMetadataEndpointColumn, EQUALS)) {
    auto constraints = context.constraints[kMetadataEndpointColumn].getAll();
    if (!constraints.empty()) {
      for (const auto& c : constraints) {
        endpoints.push_back(c.expr);
      }
    }
  }

  if (endpoints.empty()) {
    endpoints.push_back(defaultEndpoint);
  }

  for (const auto& endpoint : endpoints) {
    JSON doc;
    Row r;

    Status s = fetchYCloudMetadata(doc, endpoint);
    if (!s.ok()) {
      TLOG << "Couldn't fetch metadata: endpoint" << endpoint
           << " reason: " << s.what();
      continue;
    }

    auto [folderId, zone] =
        getFolderIdAndZoneFromZoneField(getYCloudKey(doc, "zone"));
    r["instance_id"] = getYCloudKey(doc, "id");
    r["folder_id"] = folderId;
    r["zone"] = zone;
    r["name"] = getYCloudKey(doc, "name");
    r["description"] = getYCloudKey(doc, "description");
    r["hostname"] = getYCloudKey(doc, "hostname");
    r["ssh_public_key"] = getYCloudSshKey(doc);
    r["serial_port_enabled"] = getSerialPortEnabled(doc);
    r[kMetadataEndpointColumn] = endpoint;

    results.push_back(r);
  }

  return results;
}

} // namespace tables
} // namespace osquery