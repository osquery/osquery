/*
 *  Copyright (c) 2016-present, Jean-Francois Dive <jfdive@gmail.com>
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <string>

#include "include/osquery/tables.h"

namespace osquery {
namespace tables {

/**
 * @brief SuperClass for AWS metadata accessors
 */
class AwsData {
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
  std::string DoGet();

  public:
  /**
   * @brief ctor
   */
  AwsData(ColumnType in_sqlType, std::string in_fieldName, std::string in_subUrl) {
    sqlType = in_sqlType;
    fieldName = in_fieldName;
    subUrl = in_subUrl;
  }

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
  virtual Status ExtractResult(Row& r, std::string http_body) = 0;

  /**
   * @brief HTTP get and extract data
   *
   * @param r The row to which the value need to be added
   * @return osquery Status
   */
  Status Get(Row& r) {
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

  virtual Status ExtractResult(Row& r, std::string http_body);
};

/**
 * @brief Handle IAM parsing
 */
class IamArnAwsData : public AwsData {
  public:

  IamArnAwsData(ColumnType in_sqlType, std::string in_fieldName, std::string in_subUrl) 
      : AwsData(in_sqlType, in_fieldName, in_subUrl) {}

  virtual Status ExtractResult(Row& r, std::string http_body);
};

}
}
