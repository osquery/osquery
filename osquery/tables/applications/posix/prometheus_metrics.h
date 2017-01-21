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
      : urls_(urls),
        options_(http::client::options().follow_redirects(true).timeout(
            timeoutDurationS)),
        client_(options_) {}

  virtual ~PrometheusMetrics() {}

  QueryData& queryPrometheusTargets();

 protected:
  virtual std::map<std::string, retData*> scrapeTargets();

 private:
  std::vector<std::string> urls_;
  QueryData rows_;
  http::client::options options_;
  http::client client_;

  void parseScrapeResults(std::map<std::string, retData*>& scrapeResults);
};
}
}
