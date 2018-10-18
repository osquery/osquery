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

#include "osquery/remote/http_client.h"
#include "osquery/core/json.h"

namespace osquery {
namespace tables {
  namespace http = osquery::http;
  namespace pt = boost::property_tree;

  // 2018-02-01 is supported across all Azure regions, according to MS.
  static const std::string kMetadataEndpoint = \
    "http://169.254.169.254/metadata/instance/compute?api-version=2018-02-01";

  // Azure VM IDs are unique and don't change on an instance,
  // so we can safely cache them.
  static std::string kCachedVmId;

  std::string tree_get(pt::ptree& tree, const std::string key) {
    return tree.get<std::string>(key, "");
  }

  QueryData genAzureMetadata(QueryContext& context) {
    QueryData results;
    Row r;

    http::Client client;
    http::Request request(kMetadataEndpoint);
    http::Response response;
    pt::ptree tree;

    // NOTE(ww): Unlike EC2, Azure doesn't host only POSIX systems.
    // As such, we don't have a good platform independent way
    // to confirm whether the system we're on is, in fact,
    // an Azure instance.

    request << http::Request::Header("Metadata", "true");
    response = client.get(request);

    // Azure's metadata service is known to be spotty.
    if (response.result_int() == 404) {
      TLOG << "Azure metadata service 404'd";
    }

    // Non-200s can indicate a variety of conditions, so report them.
    if (response.result_int() != 200) {
      TLOG << "Azure metadata service responded with code " << response.result();
    }

    std::stringstream json_stream;
    json_stream << response.body();
    try {
      pt::read_json(json_stream, tree);
    } catch (const pt::json_parser::json_parser_error& e) {
      TLOG << "Couldn't parse metadata JSON from: " << kMetadataEndpoint << ": " << e.what();
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
}
}
