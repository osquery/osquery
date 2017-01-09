/*
 *  Copyright (c) Jean-Francois Dive <jfdive@gmail.com>
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. 
 *
 */

#include <string>

#include <boost/network/protocol/http/client.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/noncopyable.hpp>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

namespace pt = boost::property_tree;
namespace http = boost::network::http;

namespace osquery {
namespace tables {

/**
 * @brief SuperClass for AWS metadata accessors
 */
class AwsData : public boost::noncopyable {
  protected:
  /**
   * @brief SQL type for the value
   */
  ColumnType sqlType;

  /**
   * @brief SQL column name
   */
  std::string fieldName;

  /**
   * @brief API URL
   */
  std::string subUrl;

  /**
   * @brief HTTP get the data
   *
   * @return osquery Status
   */
  std::string DoGet() const;

  public:
  /**
   * @brief ctor
   */
  AwsData(ColumnType _sqlType, std::string _fieldName, std::string _subUrl)
    : sqlType(_sqlType), fieldName(std::move(_fieldName)), subUrl(std::move(_subUrl)) {}

  /**
   * @brief dtor
   */
  virtual ~AwsData() {}

  /**
   * @brief Extract relevant data from return API call, pure virtual
   *
   * @param r The row to which the value need to be added
   * @param http_body content of the http response body
   * @return osquery Status
   */
  virtual Status ExtractResult(Row& r, std::string http_body) const = 0;

  /**
   * @brief HTTP get and extract data
   *
   * @param r The row to which the value need to be added
   * @return osquery Status
   */
  Status Get(Row& r) const {
      std::string http_body = DoGet();
      if(!http_body.empty()) {
        return ExtractResult(r, http_body);
      }
      // no hard error if no response
      return Status(0, "OK");
  }

};

/**
 * @brief handle all data not requiring parsing
 */
class GenericAwsData : public AwsData {
  public:

  GenericAwsData(ColumnType in_sqlType, std::string in_fieldName, std::string in_subUrl)
      : AwsData(in_sqlType, in_fieldName, in_subUrl) {}

  virtual Status ExtractResult(Row& r, std::string http_body) const override;
};

/**
 * @brief Handle IAM parsing
 */
class IamArnAwsData : public AwsData {
  public:

  IamArnAwsData(ColumnType in_sqlType, std::string in_fieldName, std::string in_subUrl)
      : AwsData(in_sqlType, in_fieldName, in_subUrl) {}

  virtual Status ExtractResult(Row& r, std::string http_body) const override;
};

static bool initialized = false;

// use of the ipv4 address to be region independent (vs hostname based)
const static std::string kAwsBaseUrl{"http://169.254.169.254/latest/"};

static std::vector<AwsData*> AwsFields; 

void awsMetaInit() {
    AwsFields.push_back(new GenericAwsData(TEXT_TYPE, "ami_id", "meta-data/ami-id"));
    AwsFields.push_back(new GenericAwsData(INTEGER_TYPE, "ami_launch_index", "meta-data/ami-launch-index"));
    AwsFields.push_back(new GenericAwsData(TEXT_TYPE, "ami_manifest_path", "meta-data/ami-manifest-path"));
    AwsFields.push_back(new GenericAwsData(TEXT_TYPE, "ancestor_ami_ids", "meta-data/ancestor-ami-ids"));
    AwsFields.push_back(new GenericAwsData(TEXT_TYPE, "block_device_root", "meta-data/block-device-mapping/root"));
    AwsFields.push_back(new GenericAwsData(TEXT_TYPE, "hostname", "meta-data/hostname"));
    AwsFields.push_back(new GenericAwsData(TEXT_TYPE, "instance_action", "meta-data/instance_action"));
    AwsFields.push_back(new GenericAwsData(TEXT_TYPE, "instance_id", "meta-data/instance-id"));
    AwsFields.push_back(new GenericAwsData(TEXT_TYPE, "instance_type", "meta-data/instance-type"));
    AwsFields.push_back(new GenericAwsData(TEXT_TYPE, "local_hostname", "meta-data/local-hostname"));
    AwsFields.push_back(new GenericAwsData(TEXT_TYPE, "local_ipv4", "meta-data/local-ipv4"));
    AwsFields.push_back(new GenericAwsData(TEXT_TYPE, "mac", "meta-data/mac"));
    AwsFields.push_back(new GenericAwsData(TEXT_TYPE, "availability_zone", "meta-data/placement/availability-zone"));
    AwsFields.push_back(new GenericAwsData(TEXT_TYPE, "product_codes", "meta-data/product-codes"));
    AwsFields.push_back(new GenericAwsData(TEXT_TYPE, "public_hostname", "meta-data/public-hostname"));
    AwsFields.push_back(new GenericAwsData(TEXT_TYPE, "public_ipv4", "meta-data/public-ipv4"));
    AwsFields.push_back(new GenericAwsData(TEXT_TYPE, "openssh_public_key", "meta-data/public-keys/0/openssh-key"));
    AwsFields.push_back(new GenericAwsData(TEXT_TYPE, "reservation_id", "meta-data/reservation-id"));
    AwsFields.push_back(new GenericAwsData(TEXT_TYPE, "security_group", "meta-data/security-groups"));
    AwsFields.push_back(new GenericAwsData(TEXT_TYPE, "user_data", "user-data"));
    AwsFields.push_back(new GenericAwsData(TEXT_TYPE, "iam_credential_name", "meta-data/iam/security-credentials/"));
    AwsFields.push_back(new IamArnAwsData(TEXT_TYPE, "iam_arn", "meta-data/iam/info"));
    initialized = true;
}

std::string AwsData::DoGet() const {
    std::string ret;
    std::string url = kAwsBaseUrl + subUrl;
    http::client::request req(url);
    http::client::response res;

    // http client init
    http::client::options options;
    options.timeout(3);
    http::client client(options);
    
    try {
        res = client.get(req);
    }
    catch (const std::exception& e) {
        VLOG(1) << "error in http request to " << url << " failed: " << e.what();
        return ret;
    }
    // check http status
    boost::uint16_t http_status_code = res.status(); 

    // silent ignore of 404: some AWS API REST entry points are not always available depending on AMI config
    if(http_status_code == 404) {
        return ret;
    }
    // log "hard" errors
    if(http_status_code != 200) {
        VLOG(1) << "error in http request to " << url << " http code: " << http_status_code;
        return ret;
    }
    // populate
    ret = res.body();

    return ret;
}

Status GenericAwsData::ExtractResult(Row& r, std::string http_body) const {
    switch(sqlType) {
        case TEXT_TYPE:
            r[fieldName] = TEXT(http_body.c_str());
        case INTEGER_TYPE:
            r[fieldName] = INTEGER(http_body.c_str());
            break;
        default:
            VLOG(1) << "unknown field type: " << sqlType << " for AWS object: " << subUrl;
    }
    
    return Status(0, "OK");
}

Status IamArnAwsData::ExtractResult(Row& r, std::string http_body) const {
    pt::ptree tree;
    try {
    	std::stringstream json_stream;
        json_stream << http_body;
        pt::read_json(json_stream, tree);
    } catch (const pt::json_parser::json_parser_error& e ) {
        VLOG(1) << "Could not parse Iam Arn JSON from " << subUrl << ": " << e.what();
        return Status(0, "JSON parse failure");
    }
    
    std::string val = tree.get<std::string>("InstanceProfileArn");
    r[fieldName] = TEXT(val.c_str());
 
    return Status(0, "OK");
}

QueryData genAwsMetadata(QueryContext& context) {
    Row r;
    QueryData results;

    if(!initialized) {
        awsMetaInit();
    }

    // loop around all the requests
    using AwsFieldsIter = std::vector<AwsData*>::iterator;
    for(AwsFieldsIter it = AwsFields.begin(); it != AwsFields.end(); ++it) {
        // Error is logged within
        (*it)->Get(r);
    }

    // create the full row
    results.push_back(r);

    return results;
}
}
}
