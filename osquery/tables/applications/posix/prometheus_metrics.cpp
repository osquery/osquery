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
// clang-format on

#include <sstream>

#include <osquery/config/config.h>
#include <plugins/config/parsers/prometheus_targets.h>
#include <osquery/logger/logger.h>
#include <osquery/core/tables.h>
#include <osquery/tables/applications/posix/prometheus_metrics.h>
#include <osquery/utils/conversions/split.h>

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

void parsePrometheusTargetsConfig(
    const JSON& doc,
    std::map<std::string, PrometheusResponseData>& scrapeResults,
    size_t& timeout) {
  timeout = 1;

  const auto& root = doc.doc();
  if (!root.IsObject() || !root.HasMember(kPrometheusParserRootKey)) {
    LOG(WARNING) << "Could not load prometheus_targets root key: "
                 << kPrometheusParserRootKey;
    return;
  }

  const auto& config = root[kPrometheusParserRootKey];
  if (!config.IsObject()) {
    LOG(WARNING) << "Configuration for prometheus_targets is not an object";
    return;
  }

  if (!config.HasMember("urls")) {
    LOG(WARNING)
        << "Configuration for prometheus_targets is missing field: urls";
    return;
  }

  const auto& urls = config["urls"];
  if (!urls.IsArray()) {
    LOG(WARNING)
        << "Configuration for prometheus_targets has a non-array urls field";
    return;
  }

  for (const auto& url : urls.GetArray()) {
    if (!url.IsString()) {
      LOG(WARNING) << "Configuration for prometheus_targets contains a "
                      "non-string url, skipping it";
      continue;
    }

    scrapeResults[url.GetString()] = PrometheusResponseData{};
  }

  if (config.HasMember("timeout")) {
    if (!config["timeout"].IsUint64()) {
      LOG(WARNING) << "Configuration for prometheus_targets has a non-integer "
                      "timeout field, using the default";
      return;
    }

    timeout = config["timeout"].GetUint64();
  }
}

QueryData genPrometheusMetrics(QueryContext& context) {
  QueryData result;
  // get urls from config
  auto parser = Config::getParser("prometheus_targets");
  if (parser == nullptr || parser.get() == nullptr) {
    return result;
  }

  std::map<std::string, PrometheusResponseData> sr;
  size_t timeout = 1;
  parsePrometheusTargetsConfig(parser->getData(), sr, timeout);
  scrapeTargets(sr, timeout);
  parseScrapeResults(sr, result);

  return result;
}
} // namespace tables
} // namespace osquery
