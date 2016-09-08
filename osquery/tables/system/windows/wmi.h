/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <iostream>
#include <string>
#include <vector>

#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <WbemIdl.h>

#include <osquery/tables.h>

namespace osquery {
namespace tables {

/**
* @breif Helper class to hold 1 result object from a WMI request
*
* This class is used to return to the user just the base type
* and value requested from WMI. The class is largely used by
* the WmiRequest class defined below
*/
class WmiResultItem {
 public:
  explicit WmiResultItem(IWbemClassObject* result) : result_(result){};
  WmiResultItem(WmiResultItem&& src);

  /**
  * @brief Destructor for our WMI Wrapper
  *
  * This destructor ensures to free the various pointers used
  * to keep track of IWbem Objects needed for WMI queries.
  */
  ~WmiResultItem();

  /**
  * @brief Windows WMI Helper function to print the type associated with results
  *
  * @returns None.
  */
  void PrintType(const std::string& name) const;

  /**
  * @brief Windows WMI Helper function to retrieve a bool result from a WMI
  * query
  *
  * @returns Status indiciating the success of the query
  */
  Status GetBool(const std::string& name, bool& ret) const;

  /**
  * @brief Windows WMI Helper function to retrieve a Long result from a WMI
  * query
  *
  * @returns Status indiciating the success of the query
  */
  Status GetLong(const std::string& name, long& ret) const;

  /**
  * @brief Windows WMI Helper function to retrieve an unsigned Long result from
  * a WMI query
  *
  * @returns Status indiciating the success of the query
  */
  Status GetUnsignedLong(const std::string& name, unsigned long& ret) const;

  /**
  * @brief Windows WMI Helper function to retrieve a Long Long result from a WMI
  * query
  *
  * @returns Status indiciating the success of the query
  */
  Status GetLongLong(const std::string& name, long long& ret) const;

  /**
  * @brief Windows WMI Helper function to retrieve an Unsigned Long Long result
  * from a WMI query
  *
  * @returns Status indiciating the success of the query
  */
  Status GetUnsignedLongLong(const std::string& name,
                             unsigned long long& ret) const;

  /**
  * @brief Windows WMI Helper function to retrieve a String result from a WMI
  * query
  *
  * @returns Status indiciating the success of the query
  */
  Status GetString(const std::string& name, std::string& ret) const;

  /**
  * @brief Windows WMI Helper function to retrieve a vector of String result
  * from
  * a WMI query
  *
  * @returns Status indiciating the success of the query
  */
  Status GetVectorOfStrings(const std::string& name,
                            std::vector<std::string>& ret) const;

 private:
  IWbemClassObject* result_{nullptr};
};

/**
* @brief Windows wrapper class for querying WMI
*
* This class abstracts away the WMI querying logic and
* will return WMI results given a query string.
*/
class WmiRequest {
 public:
  explicit WmiRequest(const std::string& query);
  WmiRequest(WmiRequest&& src);
  ~WmiRequest();

  std::vector<WmiResultItem>& results() {
    return results_;
  }

  /**
  * @brief Getter for retrieving the status of a WMI Request
  *
  * @returns the status of the WMI request.
  */
  Status getStatus() {
    return status_;
  }

 private:
  Status status_;
  std::vector<WmiResultItem> results_;
  IWbemLocator* locator_{nullptr};
  IWbemServices* services_{nullptr};
  IEnumWbemClassObject* enum_{nullptr};
};
}
}