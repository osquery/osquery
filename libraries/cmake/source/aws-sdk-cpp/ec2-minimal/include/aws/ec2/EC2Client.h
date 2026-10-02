/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#pragma once

#include <aws/core/client/AWSClient.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/ec2/EC2Errors.h>
#include <aws/ec2/EC2_EXPORTS.h>
#include <aws/ec2/model/DescribeTagsRequest.h>
#include <aws/ec2/model/DescribeTagsResponse.h>

namespace Aws {
namespace EC2 {

using DescribeTagsOutcome =
    Aws::Utils::Outcome<Model::DescribeTagsResponse, EC2Error>;

class AWS_EC2_API EC2Client : public Aws::Client::AWSXMLClient {
 public:
  using BASECLASS = Aws::Client::AWSXMLClient;

  EC2Client(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider>&
                credentialsProvider,
            const Aws::Client::ClientConfiguration& clientConfiguration);
  ~EC2Client() override = default;

  DescribeTagsOutcome DescribeTags(
      const Model::DescribeTagsRequest& request) const;

 private:
  void init(const Aws::Client::ClientConfiguration& config);

  Aws::String m_configScheme;
  Aws::String m_uri;
};

} // namespace EC2
} // namespace Aws