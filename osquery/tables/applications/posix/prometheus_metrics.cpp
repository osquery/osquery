/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <osquery/config.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include <osquery/tables/applications/posix/prometheus_metrics.h>
#include <osquery/tables/applications/posix/prometheus_metrics_utils.h>

namespace http = boost::network::http;

namespace osquery {
namespace tables {

void PrometheusMetrics::parseScrapeResults(
    std::map<std::string, retData*>& scrapeResults) {
  for (auto const& target : scrapeResults) {
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

std::map<std::string, retData*> PrometheusMetrics::scrapeTargets() {
  std::map<std::string, retData*> results;

  for (const auto& url : urls_) {
    try {
      retData* rd = new retData;

      http::client::request request(url);
      http::client::response response(client_.get(request));

      rd->timestampMS = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch());
      rd->content = static_cast<std::string>(body(response));

      results[url] = rd;

    } catch (std::exception& e) {
      LOG(ERROR) << "failed on scrape of target " << url
                 << " with error: " << e.what();
    }
  }

  return results;
}

QueryData& PrometheusMetrics::queryPrometheusTargets() {
  std::map<std::string, retData*> scrapeResults(scrapeTargets());

  parseScrapeResults(scrapeResults);

  // free heap mem
  for (auto& target : scrapeResults) {
    delete target.second;
  }

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
