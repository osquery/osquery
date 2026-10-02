/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include "aws/ec2/EC2Client.h"

#include <aws/core/auth/AWSAuthSigner.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/core/http/Scheme.h>
#include <aws/ec2/EC2Endpoint.h>
#include <aws/ec2/EC2ErrorMarshaller.h>

namespace Aws {
namespace EC2 {
namespace {

constexpr const char* kServiceName = "ec2";
constexpr const char* kAllocationTag = "EC2Client";

} // namespace

EC2Client::EC2Client(
    const std::shared_ptr<Aws::Auth::AWSCredentialsProvider>&
        credentialsProvider,
    const Aws::Client::ClientConfiguration& clientConfiguration)
    : BASECLASS(
          clientConfiguration,
          Aws::MakeShared<Aws::Client::AWSAuthV4Signer>(
              kAllocationTag,
              credentialsProvider,
              kServiceName,
              Aws::Region::ComputeSignerRegion(clientConfiguration.region)),
          Aws::MakeShared<Aws::Client::EC2ErrorMarshaller>(kAllocationTag)) {
  init(clientConfiguration);
}

void EC2Client::init(const Aws::Client::ClientConfiguration& config) {
  SetServiceClientName("EC2");
  m_configScheme = Aws::Http::SchemeMapper::ToString(config.scheme);
  if (config.endpointOverride.empty()) {
    m_uri =
        m_configScheme + "://" +
        Aws::EC2::EC2Endpoint::ForRegion(config.region, config.useDualStack);
  } else if (config.endpointOverride.compare(0, 7, "http://") == 0 ||
             config.endpointOverride.compare(0, 8, "https://") == 0) {
    m_uri = config.endpointOverride;
  } else {
    m_uri = m_configScheme + "://" + config.endpointOverride;
  }
}

DescribeTagsOutcome EC2Client::DescribeTags(
    const Model::DescribeTagsRequest& request) const {
  Aws::Http::URI uri = m_uri;
  return DescribeTagsOutcome(
      MakeRequest(uri, request, Aws::Http::HttpMethod::HTTP_POST));
}

} // namespace EC2
} // namespace Aws