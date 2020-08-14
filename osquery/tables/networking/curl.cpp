/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// clang-format off
// Keep it on top of all other includes to fix double include WinSock.h header file
// which is windows specific boost build problem
#include <osquery/remote/http_client.h>
#include <osquery/remote/transports/tls.h>
// clang-format on

#include <chrono>

#include <boost/numeric/conversion/cast.hpp>

#include <osquery/logger/logger.h>
#include <osquery/utils/status/status.h>
#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

const std::string kOsqueryUserAgent{"osquery"};

Status processRequest(Row& r) {
  try {
    osquery::http::Client client(TLSTransport().getOptions());
    osquery::http::Response response;
    osquery::http::Request request(r["url"]);

    // Change the user-agent for the request to be osquery
    request << osquery::http::Request::Header("User-Agent", r["user_agent"]);

    // Measure the rtt using the system clock
    auto time_start = std::chrono::system_clock::now();
    response = client.get(request);
    auto time_end = std::chrono::system_clock::now();

    r["response_code"] = INTEGER(static_cast<int>(response.status()));
    r["round_trip_time"] =
        BIGINT(std::chrono::duration_cast<std::chrono::microseconds>(time_end -
                                                                     time_start)
                   .count());
    r["result"] = response.body();
    r["bytes"] = BIGINT(r["result"].size());
  } catch (const std::exception& e) {
    return Status::failure(e.what());
  }

  return Status::success();
}

QueryData genCurl(QueryContext& context) {
  QueryData results;

  auto requests = context.constraints["url"].getAll(EQUALS);
  auto user_agents = context.constraints["user_agent"].getAll(EQUALS);

  if (user_agents.size() > 1) {
    LOG(WARNING) << "Can only accept a single user_agent";
    return results;
  }

  // Using the like clause for urls wouldn't make sense
  if (context.constraints["url"].getAll(LIKE).size()) {
    LOG(WARNING) << "Using LIKE clause for url is not supported";
  }

  for (const auto& request : requests) {
    Row r;
    r["url"] = request;
    r["method"] = "GET";
    r["user_agent"] =
        user_agents.empty() ? kOsqueryUserAgent : *(user_agents.begin());

    auto status = processRequest(r);
    if (!status.ok()) {
      LOG(WARNING) << "Error making request: " << status.getMessage();
    }

    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery
