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

#include <chrono>
#include <map>
#include <string>
#include <vector>

#include <osquery/tables.h>

#include <boost/network/protocol/http/client.hpp>

namespace http = boost::network::http;

namespace osquery {
namespace tables {

const std::string col_target_name = "target_name";
const std::string col_metric = "metric_name";
const std::string col_value = "metric_value";
const std::string col_timestamp = "timestamp_ms";

struct retData {
  std::string content;
  std::chrono::milliseconds timestampMS;
};

class PrometheusMetrics {
 public:
  PrometheusMetrics(std::vector<std::string> urls, int timeoutDurationS = 1)
      : options_(http::client::options().follow_redirects(true).timeout(
            timeoutDurationS)),
        client_(options_) {
    for (const auto& url : urls) {
      retData* rd = new retData;
      scrapeResults_[url] = rd;
    }
  }

  virtual ~PrometheusMetrics() {
    for (auto& target : scrapeResults_) {
      delete target.second;
    }
  }

  QueryData& queryPrometheusTargets();

 protected:
  /**
  * @brief Constructor to be used by derived classes for testing.
  *
  * @param Stubbed scrapeResults with scraped content already injected.
  *
   */
  PrometheusMetrics(std::map<std::string, retData*> stubbedSR)
      : scrapeResults_(stubbedSR) {}

 private:
  std::map<std::string, retData*> scrapeResults_;
  QueryData rows_;
  http::client::options options_;
  http::client client_;

  virtual void scrapeTargets();
  void parseScrapeResults();
};
}
}
