/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/network/include/http/client.hpp>
#include <boost/numeric/conversion/cast.hpp>
#include <chrono>
#include <osquery/tables.h>

#include <stdio.h>

using namespace boost::network::http;
using namespace std::chrono;

namespace osquery {
namespace tables {

void processRequest(const std::string& request_str, QueryData& results) {
  Row r;
  r["url"] = request_str;
  r["method"] = "GET";
  r["ua"] = "osquery";

  try {
    client client_;
    client::request request_(request_str);
    time_point<system_clock> start = std::chrono::system_clock::now();
    client::response response_ = client_.get(request_);
    time_point<system_clock> end = std::chrono::system_clock::now();
    r["response_code"] = BIGINT(static_cast<int>(status(response_)));
    r["rtt"] = BIGINT(microseconds(end - start).count());

    // This usually destroys the UI since responses are long
    // r["result"] = static_cast<std::string>(body(response_));

    r["bytes"] = BIGINT((static_cast<std::string>(body(response_))).size());
    results.push_back(r);
  } catch (std::exception& e) {
    std::cerr << "Exception: " << e.what() << std::endl;
  }
}

QueryData genCurl(QueryContext& context) {
  QueryData results;

  auto requests = context.constraints["url"].getAll(EQUALS);

  for (const auto& request : requests) {
    processRequest(request, results);
  }

  return results;
}
} // namespace tables
} // namespace osquery
