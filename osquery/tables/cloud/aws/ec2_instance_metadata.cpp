/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/remote/http_client.h>

#include <string>

#include <boost/algorithm/string.hpp>
#include <boost/noncopyable.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/aws/aws_util.h>

namespace pt = boost::property_tree;

namespace osquery {

DECLARE_bool(aws_disable_imdsv1_fallback);
namespace tables {

/**
 * @brief Super class for EC2 metadata accessors
 */
class Ec2MetaData {
 protected:
  /**
   * @brief Meta data URL suffix
   */
  const std::string url_suffix_;

  /**
   * @brief Get metadata using HTTP.
   *
   * @return HTTP body.
   */
  std::string doGet() const;

  /**
   * @brief Extract relevant data from return API call, pure virtual
   *
   * @param http_body content of the http response body
   * @param r The row to which the value need to be added
   */
  virtual void extractResult(const std::string& http_body, Row& r) const = 0;

 public:
  Ec2MetaData(const std::string urlSuffix)
      : url_suffix_(std::move(urlSuffix)) {}

  virtual ~Ec2MetaData() {}

  /**
   * @brief HTTP get and extract data
   *
   * @param r The row to which the value need to be added
   */
  void get(Row& r) const {
    const std::string http_body = doGet();

    if (http_body.empty()) {
      LOG(ERROR) << "Failed to get instance metadata from the metadata service";
      return;
    }

    extractResult(http_body, r);
  }
};

/**
 * @brief handle all data not requiring parsing
 */
class SimpleEc2MetaData : public Ec2MetaData {
 protected:
  /**
   * @brief SQL type for the value
   */
  const ColumnType sql_type_;

  /**
   * @brief SQL column name
   */
  const std::string column_name_;

  virtual void extractResult(const std::string& http_body,
                             Row& r) const override;

 public:
  SimpleEc2MetaData(const ColumnType sqlType,
                    const std::string columnName,
                    const std::string urlSuffix)
      : Ec2MetaData(urlSuffix),
        sql_type_(std::move(sqlType)),
        column_name_(std::move(columnName)) {}

  virtual ~SimpleEc2MetaData() {}
};

/**
 * @brief Handle IAM parsing
 */
class JSONEc2MetaData : public Ec2MetaData {
 protected:
  /**
   * @brief SQL column names
   */
  const std::vector<std::string> column_names_;

  /**
   * @brief JSON key names
   */
  const std::vector<std::string> key_names_;

  virtual void extractResult(const std::string& http_body,
                             Row& r) const override;

 public:
  JSONEc2MetaData(const std::vector<std::string> columnNames,
                  const std::vector<std::string> keyNames,
                  const std::string urlSuffix)
      : Ec2MetaData(urlSuffix),
        column_names_(std::move(columnNames)),
        key_names_(std::move(keyNames)) {}

  virtual ~JSONEc2MetaData() {}
};

std::string Ec2MetaData::doGet() const {
  const static std::string ec2_metadata_url{kEc2MetadataUrl};

  auto opt_token = getIMDSToken();
  http::Request req(ec2_metadata_url + url_suffix_);

  if (opt_token.has_value()) {
    req << http::Request::Header(kImdsTokenHeader, *opt_token);
  } else if (FLAGS_aws_disable_imdsv1_fallback) {
    /* If the IMDSv2 token cannot be retrieved and we disabled IMDSv1,
       we cannot attempt to do a request, so return with empty results. */
    VLOG(1) << "Could not retrieve an IMDSv2 token to request the instance id "
               "and region. The IMDSv1 fallback is disabled";
    return {};
  }

  http::Client::Options options;
  options.timeout(3);
  http::Client client(options);

  try {
    http::Response res = client.get(req);
    boost::uint16_t http_status_code = res.status();

    // Silently ignore 404
    if (http_status_code == 404) {
      return {};
    }

    // Log "hard" errors
    if (http_status_code != 200) {
      VLOG(1) << "Unexpected HTTP response for: " << url_suffix_
              << " Status: " << http_status_code;
      return {};
    }

    return res.body();
  } catch (std::system_error& e) {
    VLOG(1) << "Request for " << url_suffix_ << " failed: " << e.what();
  }

  return "";
}

void setRowField(const ColumnType sql_type,
                 const std::string& column_name,
                 const std::string& value,
                 Row& r) {
  switch (sql_type) {
  case TEXT_TYPE: {
    std::string field_value{value};
    // Remove trailing new line, if any
    field_value.erase(std::remove(field_value.begin(), field_value.end(), '\n'),
                      field_value.end());
    // Join multi-line values
    boost::replace_all(field_value, "\n", ",");
    r[column_name] = field_value;
    break;
  }
  case INTEGER_TYPE: {
    r[column_name] = value.empty() ? INTEGER(0) : INTEGER(value);
    break;
  }
  default:
    VLOG(1) << "Unknown field type " << sql_type << " for: " << column_name;
  }
}

void SimpleEc2MetaData::extractResult(const std::string& http_body,
                                      Row& r) const {
  return setRowField(sql_type_, column_name_, http_body, r);
}

void JSONEc2MetaData::extractResult(const std::string& http_body,
                                    Row& r) const {
  try {
    std::stringstream json_stream;
    json_stream << http_body;
    pt::ptree tree;
    pt::read_json(json_stream, tree);
    for (size_t i = 0; i < column_names_.size(); i++) {
      setRowField(TEXT_TYPE,
                  column_names_[i],
                  tree.get<std::string>(key_names_[i], ""),
                  r);
    }
  } catch (const pt::json_parser::json_parser_error& e) {
    VLOG(1) << "Could not parse JSON from " << url_suffix_ << ": " << e.what();
  }
}

QueryData genEc2Metadata(QueryContext& context) {
  QueryData results;

  const static std::vector<std::shared_ptr<Ec2MetaData>> fields(
      {std::make_shared<JSONEc2MetaData>(
           JSONEc2MetaData(std::vector<std::string>({"instance_id",
                                                     "instance_type",
                                                     "local_ipv4",
                                                     "availability_zone",
                                                     "region",
                                                     "account_id",
                                                     "architecture",
                                                     "ami_id"}),
                           std::vector<std::string>({"instanceId",
                                                     "instanceType",
                                                     "privateIp",
                                                     "availabilityZone",
                                                     "region",
                                                     "accountId",
                                                     "architecture",
                                                     "imageId"}),
                           "dynamic/instance-identity/document")),
       std::make_shared<JSONEc2MetaData>(
           JSONEc2MetaData(std::vector<std::string>({"iam_arn"}),
                           std::vector<std::string>({"InstanceProfileArn"}),
                           "meta-data/iam/info")),
       std::make_shared<SimpleEc2MetaData>(
           SimpleEc2MetaData(TEXT_TYPE, "mac", "meta-data/mac")),
       std::make_shared<SimpleEc2MetaData>(SimpleEc2MetaData(
           TEXT_TYPE, "local_hostname", "meta-data/local-hostname")),
       std::make_shared<SimpleEc2MetaData>(SimpleEc2MetaData(
           TEXT_TYPE, "ssh_public_key", "meta-data/public-keys/0/openssh-key")),
       std::make_shared<SimpleEc2MetaData>(SimpleEc2MetaData(
           TEXT_TYPE, "reservation_id", "meta-data/reservation-id")),
       std::make_shared<SimpleEc2MetaData>(SimpleEc2MetaData(
           TEXT_TYPE, "security_groups", "meta-data/security-groups"))});

  Row r;
  for (const auto& it : fields) {
    it->get(r);
  }

  results.push_back(r);
  return results;
}
} // namespace tables
} // namespace osquery
