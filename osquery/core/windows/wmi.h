/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <osquery/utils/system/system.h>

#include <WbemIdl.h>

#include <osquery/tables.h>

namespace osquery {

using WmiMethodArgsMap = std::unordered_map<std::string, VARIANT>;

namespace impl {

const auto wmiObjectDeleter = [](auto* ptr) {
  if (ptr != nullptr) {
    ptr->Release();
  }
};

} // namespace impl

/**
 * @brief Helper class to construct and hold the arguments of a WMI method call
 *
 * This class is used somewhat exclusively with WmiResultItem::ExecMethod. It
 * simplifies the construction of a WMI method argument
 */
class WmiMethodArgs {
 public:
  WmiMethodArgs() {}

  WmiMethodArgs(WmiMethodArgs&& src);
  WmiMethodArgs(WmiMethodArgs&) = delete;

  ~WmiMethodArgs();

  /**
   * @brief Helper function to add items to the arguments of a WMI method call
   *
   * @returns Status indicating the success of the query
   */
  template <typename T>
  Status Put(const std::string& name, const T& value);

  /**
   * @brief Getter method for argument dictionary
   *
   * @returns Map containing name, value pairs of the arguments
   */
  const WmiMethodArgsMap& GetArguments() const {
    return arguments;
  }

 private:
  WmiMethodArgsMap arguments{};
};

/**
 * @brief Helper class to hold 1 result object from a WMI request
 *
 * This class is used to return to the user just the base type
 * and value requested from WMI. The class is largely used by
 * the WmiRequest class defined below
 */
class WmiResultItem {
 public:
  explicit WmiResultItem(IWbemClassObject* result,
                         std::shared_ptr<IWbemServices> services)
      : services_(services) {
    result_.reset(result);
  }

  WmiResultItem(WmiResultItem&& src) = default;

  /**
   * @brief Windows WMI Helper function to print the type associated with
   * results
   *
   * @returns None.
   */
  void PrintType(const std::string& name) const;

  /**
   * @brief Windows WMI Helper function to retrieve a bool result from a WMI
   * query
   *
   * @returns Status indicating the success of the query
   */
  Status GetBool(const std::string& name, bool& ret) const;

  /**
   * @brief Windows WMI Helper function to retrieve a local/non-local FILETIME
   * from WMI query.
   *
   * @returns Status indiciating the success of the query
   */
  Status GetDateTime(const std::string& name,
                     bool is_local,
                     FILETIME& ft) const;

  /**
   * @brief Windows WMI Helper function to retrieve an unsigned Char from WMI
   * query
   *
   * @returns Status indiciating the success of the query
   */
  Status GetUChar(const std::string& name, unsigned char& ret) const;

  /**
   * @brief Windows WMI Helper function to retrieve an unsigned Short from WMI
   * query
   *
   * @returns Status indiciating the success of the query
   */
  Status GetUnsignedShort(const std::string& name, unsigned short& ret) const;

  /**
   * @brief Windows WMI Helper function to retrieve an unsigned 32 bit integer
   * from a WMI query
   *
   * @returns Status indicating the success of the query
   */
  Status GetUnsignedInt32(const std::string& name, unsigned int& ret) const;

  /**
   * @brief Windows WMI Helper function to retrieve a Long result from a WMI
   * query
   *
   * @returns Status indicating the success of the query
   */
  Status GetLong(const std::string& name, long& ret) const;

  /**
   * @brief Windows WMI Helper function to retrieve an unsigned Long result from
   * a WMI query
   *
   * @returns Status indicating the success of the query
   */
  Status GetUnsignedLong(const std::string& name, unsigned long& ret) const;

  /**
   * @brief Windows WMI Helper function to retrieve a Long Long result from a
   * WMI query
   *
   * @returns Status indicating the success of the query
   */
  Status GetLongLong(const std::string& name, long long& ret) const;

  /**
   * @brief Windows WMI Helper function to retrieve an Unsigned Long Long result
   * from a WMI query
   *
   * @returns Status indicating the success of the query
   */
  Status GetUnsignedLongLong(const std::string& name,
                             unsigned long long& ret) const;

  /**
   * @brief Windows WMI Helper function to retrieve a String result from a WMI
   * query
   *
   * @returns Status indicating the success of the query
   */
  Status GetString(const std::string& name, std::string& ret) const;

  /**
   * @brief Windows WMI Helper function to retrieve a vector of String result
   * from
   * a WMI query
   *
   * @returns Status indicating the success of the query
   */
  Status GetVectorOfStrings(const std::string& name,
                            std::vector<std::string>& ret) const;

  /**
   * @brief Windows WMI Helper function to execute a WMI method call from the
   * resultant object
   *
   * @returns Status indicating the success of the query
   */
  Status ExecMethod(const std::string& method,
                    const WmiMethodArgs& args,
                    WmiResultItem& out_result) const;

 private:
  std::unique_ptr<IWbemClassObject, decltype(impl::wmiObjectDeleter)> result_{
      nullptr, impl::wmiObjectDeleter};
  std::shared_ptr<IWbemServices> services_{static_cast<IWbemServices*>(nullptr),
                                           impl::wmiObjectDeleter};
};

/**
 * @brief Windows wrapper class for querying WMI
 *
 * This class abstracts away the WMI querying logic and
 * will return WMI results given a query string.
 */
class WmiRequest {
 public:
  explicit WmiRequest(const std::string& query,
                      BSTR nspace = (BSTR)L"ROOT\\CIMV2");
  WmiRequest(WmiRequest&& src) = default;
  ~WmiRequest();

  const std::vector<WmiResultItem>& results() const {
    return results_;
  }

  /**
   * @brief Getter for retrieving the status of a WMI Request
   *
   * @returns the status of the WMI request.
   */
  Status getStatus() const {
    return status_;
  }

 private:
  Status status_;
  std::vector<WmiResultItem> results_;

  std::unique_ptr<IWbemLocator, decltype(impl::wmiObjectDeleter)> locator_{
      nullptr, impl::wmiObjectDeleter};
  std::unique_ptr<IEnumWbemClassObject, decltype(impl::wmiObjectDeleter)> enum_{
      nullptr, impl::wmiObjectDeleter};
  std::shared_ptr<IWbemServices> services_{static_cast<IWbemServices*>(nullptr),
                                           impl::wmiObjectDeleter};
};
} // namespace osquery
