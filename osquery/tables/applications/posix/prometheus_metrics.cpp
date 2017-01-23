/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <sstream>

#include <osquery/config.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include <osquery/tables/applications/posix/prometheus_metrics.h>
#include <osquery/tables/applications/posix/prometheus_metrics_utils.h>

namespace http = boost::network::http;

namespace osquery {
namespace tables {

void PrometheusMetrics::parseScrapeResults() {
  for (auto const& target : scrapeResults_) {
    std::stringstream ss(target.second->content);
    std::string dest;
    std::string ts(std::to_string(target.second->timestampMS.count()));

    while (std::getline(ss, dest)) {
      if (dest[0] != '#') {
        std::stringstream iss(dest);
        std::string idest;
        std::vector<std::string> metric;

        while (std::getline(iss, idest, ' ')) {
          if (dest != "") {
            metric.push_back(idest);
          }
        }

        if (metric.size() > 1) {
          Row r;
          r[col_target_name] = target.first;
          r[col_timestamp] = ts;
          r[col_metric] = metric[0];
          r[col_value] = metric[1];

          rows_.push_back(r);
        }
      }
    }
  }
}

void PrometheusMetrics::scrapeTargets() {
  for (auto& target : scrapeResults_) {
    try {
      http::client::request request(target.first);
      http::client::response response(client_.get(request));

      target.second->timestampMS =
          std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::system_clock::now().time_since_epoch());
      target.second->content = static_cast<std::string>(body(response));

    } catch (std::exception& e) {
      LOG(ERROR) << "failed on scrape of target " << target.first
                 << " with error: " << e.what();
    }
  }
}

QueryData& PrometheusMetrics::queryPrometheusTargets() {
  scrapeTargets();
  parseScrapeResults();

  return rows_;
}

QueryData genPrometheusMetrics(QueryContext& context) {
  QueryData result;
  // get urls from config
  auto parser = Config::getParser("prometheus_targets");
  if (parser == nullptr || parser.get() == nullptr) {
    return result;
  }

  const auto& config = parser->getData().get_child(configParserRootKey);

  if (config.count("urls") == 0) {
    return result;
  }

  const auto& urls = config.get_child("urls");
  std::vector<std::string> iurls;
  for (const auto& url : urls) {
    if (!url.first.empty()) {
      return result;
    }

    iurls.push_back(url.second.data());
  }

  PrometheusMetrics pm(iurls);

  result = pm.queryPrometheusTargets();

  return result;
}
}
}
