/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

#include <aws/core/utils/Outcome.h>
#include <aws/ec2/EC2Client.h>
#include <aws/ec2/model/DescribeTagsRequest.h>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/aws/aws_util.h>

namespace osquery {
namespace tables {

namespace ec2 = Aws::EC2;
namespace model = Aws::EC2::Model;

QueryData genEc2InstanceTags(QueryContext& context) {
  QueryData results;
  std::string instance_id, region;
  getInstanceIDAndRegion(instance_id, region);
  if (instance_id.empty() || region.empty()) {
    return results;
  }

  std::shared_ptr<ec2::EC2Client> client;
  Status s = makeAWSClient<ec2::EC2Client>(client, region, false);
  if (!s.ok()) {
    VLOG(1) << "Failed to create EC2 client: " << s.what();
    return results;
  }

  model::Filter filter;
  filter.WithName("resource-id").AddValues(instance_id);

  model::DescribeTagsRequest request;
  request.SetMaxResults(50); // Max tags per EC2 instance
  request.AddFilters(filter);

  model::DescribeTagsOutcome outcome = client->DescribeTags(request);
  if (!outcome.IsSuccess()) {
    VLOG(1) << "Error getting EC2 instance tags: "
            << outcome.GetError().GetMessage();
    return results;
  }

  model::DescribeTagsResponse response = outcome.GetResult();
  for (const auto& it : response.GetTags()) {
    Row r;
    r["instance_id"] = instance_id;
    r["key"] = SQL_TEXT(it.GetKey());
    r["value"] = SQL_TEXT(it.GetValue());
    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery
