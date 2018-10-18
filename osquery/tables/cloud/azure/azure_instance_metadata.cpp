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
    "http://169.254.169.254/metadata/instance?api-version=2018-02-01";

  std::string tree_get(pt::ptree& tree, const std::string key) {
    return tree.get<std::string>(key, "");
  }

  QueryData genAzureMetadata(QueryContext& context) {
    QueryData results;

    // NOTE(ww): Unlike EC2, Azure isn't POSIX-only.
    // As such, we don't have a good platform independent way
    // to confirm whether the system we're on is, in fact,
    // an Azure instance.

    http::Client client;
    http::Request request(kMetadataEndpoint);
    http::Response response;

    request << http::Request::Header("Metadata", "true");
    response = client.get(request);

    // Azure's metadata service is known to be spotty.
    if (response.result_int() == 404) {
      return results;
    }

    // Non-200s can indicate a variety of conditions, so report them.
    if (response.result_int() != 200) {
      TLOG << "Azure metadata service responded with code " << response.result();
      return results;
    }

    std::stringstream json_stream;
    json_stream << response.body();
    pt::ptree tree;
    try {
      pt::read_json(json_stream, tree);
    } catch (const pt::json_parser::json_parser_error& e) {
      TLOG << "Couldn't parse metadata JSON from: " << kMetadataEndpoint << ": " << e.what();
      return results;
    }

    Row r;
    r["location"] = tree_get(tree, "compute.location");
    r["name"] = tree_get(tree, "compute.name");
    r["offer"] = tree_get(tree, "compute.offer");
    r["publisher"] = tree_get(tree, "compute.publisher");
    r["sku"] = tree_get(tree, "compute.sku");
    r["version"] = tree_get(tree, "compute.version");
    r["os_type"] = tree_get(tree, "compute.osType");
    r["platform_update_domain"] = tree_get(tree, "compute.platformUpdateDomain");
    r["platform_fault_domain"] = tree_get(tree, "compute.platformFaultDomain");
    r["vm_id"] = tree_get(tree, "compute.vmId");
    r["vm_size"] = tree_get(tree, "compute.vmSize");
    r["subscription_id"] = tree_get(tree, "compute.subscriptionId");
    r["resource_group_name"] = tree_get(tree, "compute.resourceGroupName");
    r["placement_group_id"] = tree_get(tree, "compute.placementGroupId");
    r["plan"] = tree_get(tree, "compute.plan");
    r["public_keys"] = tree_get(tree, "compute.publicKeys");
    r["vm_scale_set_name"] = tree_get(tree, "compute.vmScaleSetName");
    r["zone"] = tree_get(tree, "compute.zone");

    results.push_back(r);

    return results;
  }
}
}
