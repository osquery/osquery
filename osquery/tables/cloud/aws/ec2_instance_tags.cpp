/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <aws/ec2/EC2Client.h>
#include <aws/ec2/model/DescribeTagsRequest.h>
#include <aws/ec2/model/Filter.h>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/aws/aws_util.h>

namespace osquery {
namespace tables {

namespace ec2 = Aws::EC2;
namespace model = Aws::EC2::Model;

QueryData genEc2InstanceTags(QueryContext& context) {
  QueryData results;

  auto opt_instance_info = getInstanceIDAndRegion();

  if (!opt_instance_info.has_value()) {
    LOG(WARNING) << "Failed to retrieve region and instance id";
    return results;
  }

  const auto& [instance_id, region] = *opt_instance_info;

  if (instance_id.empty() || region.empty()) {
    LOG(WARNING) << "Instance id and region are empty, returning no results";
    return results;
  }

  auto aws_region_res = AWSRegion::make(region, false);

  if (aws_region_res.isError()) {
    LOG(WARNING) << "Invalid region used to get EC2 instance tag: "
                 << aws_region_res.getError();
    return results;
  }

  initAwsSdk();

  Aws::Client::ClientConfiguration client_config;
  Status s = setAwsClientConfig(
      aws_region_res.get(), AWSServiceType::EC2, "", client_config);
  if (!s.ok()) {
    LOG(WARNING) << "Failed to configure EC2 client: " << s.what();
    return results;
  }

  auto client = std::make_shared<ec2::EC2Client>(
      std::make_shared<OsqueryAWSCredentialsProviderChain>(false),
      client_config);

  model::Filter filter;
  filter.WithName("resource-id").AddValues(instance_id);

  model::DescribeTagsRequest request;
  request.SetMaxResults(50);
  request.AddFilters(filter);

  auto outcome = client->DescribeTags(request);
  if (!outcome.IsSuccess()) {
    VLOG(1) << "Error getting EC2 instance tags: "
            << outcome.GetError().GetMessage();
    return results;
  }

  for (const auto& tag : outcome.GetResult().GetTags()) {
    Row r;
    r["instance_id"] = instance_id;
    r["key"] = SQL_TEXT(tag.GetKey());
    r["value"] = SQL_TEXT(tag.GetValue());
    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery
