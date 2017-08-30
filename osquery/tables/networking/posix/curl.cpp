/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <chrono>

#include <boost/network/include/http/client.hpp>
#include <boost/numeric/conversion/cast.hpp>

#include <osquery/logger.h>
#include <osquery/status.h>
#include <osquery/tables.h>

using namespace boost::network;
using namespace boost::network::http;
using namespace std::chrono;

namespace osquery {
namespace tables {

const std::string OSQUERY_USER_AGENT = "osquery";

Status processRequest(const std::string& request_str, QueryData& results) {
  Row r;
  r["url"] = request_str;
  r["method"] = "GET";
  r["ua"] = OSQUERY_USER_AGENT;

  try {
    client client_;
    client::response response_;
    client::request request_(request_str);

    // Change the user-agent for the request to be osquery
    request_ << header("User-Agent", OSQUERY_USER_AGENT);

    // Measure the rtt using the system clock
    time_point<system_clock> start = std::chrono::system_clock::now();
    response_ = client_.get(request_);
    time_point<system_clock> end = std::chrono::system_clock::now();

    r["response_code"] = INTEGER(static_cast<int>(status(response_)));
    r["rtt"] = BIGINT(duration_cast<microseconds>(end - start).count());
    r["result"] = static_cast<std::string>(body(response_));
    r["bytes"] = BIGINT(r["result"].size());
    results.push_back(r);
  } catch (const std::exception& e) {
    return Status(1, e.what());
  }

  return Status();
}

QueryData genCurl(QueryContext& context) {
  QueryData results;

  auto requests = context.constraints["url"].getAll(EQUALS);

  // Using the like clause for urls wouldn't make sense
  if (context.constraints["url"].getAll(LIKE).size()) {
    LOG(WARNING) << "Using like clause for url is not supported";
  }

  for (const auto& request : requests) {
    auto status = processRequest(request, results);
    if (!status.ok()) {
      LOG(WARNING) << status.getMessage();
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery
