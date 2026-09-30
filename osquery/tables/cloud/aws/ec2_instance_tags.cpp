/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

#include <aws/core/auth/AWSAuthSigner.h>
#include <aws/core/http/HttpClientFactory.h>
#include <aws/core/http/HttpResponse.h>
#include <aws/core/http/standard/StandardHttpRequest.h>
#include <aws/core/utils/StringUtils.h>
#include <aws/core/utils/memory/stl/AWSStringStream.h>
#include <aws/core/utils/xml/XmlSerializer.h>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/aws/aws_util.h>

namespace osquery {
namespace tables {

namespace {
const char kEc2ApiVersion[] = "2016-11-15";

std::string getEc2Endpoint(const Aws::Client::ClientConfiguration& config) {
  if (!config.endpointOverride.empty()) {
    return config.endpointOverride;
  }

  return "ec2." + std::string(config.region) + ".amazonaws.com";
}

std::string getResponseBody(Aws::Http::HttpResponse& response) {
  std::stringstream body;
  body << response.GetResponseBody().rdbuf();
  return body.str();
}
} // namespace

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

  Aws::Http::URI uri("https://" + getEc2Endpoint(client_config));
  auto request =
      std::make_shared<Aws::Http::Standard::StandardHttpRequest>(
          uri, Aws::Http::HttpMethod::HTTP_POST);

  Aws::StringStream payload;
  payload << "Action=DescribeTags"
          << "&Version=" << kEc2ApiVersion
          << "&MaxResults=50"
          << "&Filter.1.Name=resource-id"
          << "&Filter.1.Value.1="
          << Aws::Utils::StringUtils::URLEncode(instance_id.c_str());

  auto body = Aws::MakeShared<Aws::StringStream>("Ec2InstanceTags");
  *body << payload.str();
  request->AddContentBody(body);
  request->SetContentLength(std::to_string(payload.str().size()).c_str());
  request->SetContentType("application/x-www-form-urlencoded; charset=utf-8");

  Aws::Client::AWSAuthV4Signer signer(
      std::make_shared<OsqueryAWSCredentialsProviderChain>(false),
      "ec2",
      client_config.region,
      Aws::Client::AWSAuthV4Signer::PayloadSigningPolicy::Always);

  if (!signer.SignRequest(*request)) {
    LOG(WARNING) << "Failed to sign EC2 DescribeTags request";
    return results;
  }

  OsqueryHttpClient client;
  auto response = client.MakeRequest(request, nullptr, nullptr);
  if (response->GetResponseCode() != Aws::Http::HttpResponseCode::OK) {
    VLOG(1) << "Error getting EC2 instance tags, HTTP response code: "
            << static_cast<int>(response->GetResponseCode());
    return results;
  }

  auto xml = Aws::Utils::Xml::XmlDocument::CreateFromXmlString(
      getResponseBody(*response).c_str());
  if (!xml.WasParseSuccessful()) {
    VLOG(1) << "Error parsing EC2 instance tags response: "
            << xml.GetErrorMessage();
    return results;
  }

  auto root = xml.GetRootElement();
  auto result_node = root;
  if (!root.IsNull() && root.GetName() != "DescribeTagsResponse") {
    result_node = root.FirstChild("DescribeTagsResponse");
  }

  if (result_node.IsNull()) {
    return results;
  }

  auto tags_node = result_node.FirstChild("tagSet");
  if (tags_node.IsNull()) {
    return results;
  }

  auto tag = tags_node.FirstChild("item");
  while (!tag.IsNull()) {
    Row r;
    r["instance_id"] = instance_id;
    r["key"] = SQL_TEXT(Aws::Utils::Xml::DecodeEscapedXmlText(
        tag.FirstChild("key").GetText()));
    r["value"] = SQL_TEXT(Aws::Utils::Xml::DecodeEscapedXmlText(
        tag.FirstChild("value").GetText()));
    results.push_back(r);
    tag = tag.NextNode("item");
  }

  return results;
}
} // namespace tables
} // namespace osquery
