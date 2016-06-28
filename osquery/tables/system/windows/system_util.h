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

#include <string>
#include <vector>
#include <iostream>

#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <WbemIdl.h>

#include <osquery/tables.h>

namespace osquery {
namespace tables {
 
class WmiResultItem {
 public:
  explicit WmiResultItem(IWbemClassObject *result) : result_(result) {};
  WmiResultItem(WmiResultItem&& src);
  ~WmiResultItem();

  long GetLong(const std::string& name) const;
  std::string GetString(const std::string& name) const;
  void PrintType(const std::string& name) const;

 private:
   IWbemClassObject *result_{ nullptr };
};

class WmiRequest {
 public:
  explicit WmiRequest(const std::string& query);
  WmiRequest(WmiRequest&& src);
  ~WmiRequest();

  bool ok() { return status_; }
  std::vector<WmiResultItem>& results() { return results_; }

 private:
   bool status_{ false };
   std::vector<WmiResultItem> results_;

   IWbemLocator *locator_{ nullptr };
   IWbemServices *services_{ nullptr };
   IEnumWbemClassObject *enum_{ nullptr };
};
}
}