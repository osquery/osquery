/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */
#include <sstream>

#include <osquery/config.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/config/parsers/prometheus_targets.h"
#include "osquery/core/conversions.h"
#include "osquery/remote/http_client.h"
#include "osquery/tables/applications/posix/prometheus_metrics.h"

namespace osquery {
namespace tables {

void parseScrapeResults(
    const std::map<std::string, PrometheusResponseData>& scrapeResults,
    QueryData& rows) {
  for (auto const& target : scrapeResults) {
    std::stringstream ss(target.second.content);
    std::string dest;

    while (std::getline(ss, dest)) {
      if (!dest.empty() && dest[0] != '#') {
        auto metric(osquery::split(dest, " "));

        if (metric.size() > 1) {
          Row r;
          r[kColTargetName] = target.first;
          r[kColTimeStamp] = BIGINT(target.second.timestampMS.count());
          r[kColMetric] = metric[0];
          r[kColValue] = metric[1];

          rows.push_back(r);
        }
      }
    }
  }
}

void scrapeTargets(std::map<std::string, PrometheusResponseData>& scrapeResults,
                   size_t timeoutS) {
  http::Client client(
      http::Client::Options().follow_redirects(true).timeout(timeoutS));

  for (auto& target : scrapeResults) {
    try {
      http::Request request(target.first);
      http::Response response(client.get(request));

      target.second.timestampMS =
          std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::system_clock::now().time_since_epoch());
      target.second.content = response.body();

    } catch (std::exception& e) {
      LOG(ERROR) << "Failed on scrape of target " << target.first << ": "
                 << e.what();
    }
  }
}

QueryData genPrometheusMetrics(QueryContext& context) {
  QueryData result;
  // get urls from config
  auto parser = Config::getParser("prometheus_targets");
  if (parser == nullptr || parser.get() == nullptr) {
    return result;
  }

  /* Add a specific value to the default property tree to differentiate it from
   * the scenario where the user does not provide any prometheus_targets config.
   */
  const auto& root = parser->getData().doc();
  if (!root.HasMember(kPrometheusParserRootKey)) {
    LOG(WARNING) << "Could not load prometheus_targets root key: "
                 << kPrometheusParserRootKey;
    return result;
  }

  const auto& config = root[kPrometheusParserRootKey];
  if (!config.HasMember("urls")) {
    LOG(WARNING)
        << "Configuration for prometheus_targets is missing field: urls";
    return result;
  }

  std::map<std::string, PrometheusResponseData> sr;
  /* Below should be unreachable if there were no urls child node, but we set
   * handle with default value for consistency's sake and for added robustness.
   */
  const auto& urls = config["urls"];
  for (const auto& url : urls.GetArray()) {
    sr[url.GetString()] = PrometheusResponseData{};
  }

  size_t timeout =
      (!config.HasMember("timeout")) ? 1 : config["timeout"].GetUint64();
  scrapeTargets(sr, timeout);
  parseScrapeResults(sr, result);

  return result;
}
}
}
