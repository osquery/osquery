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

#include <curl/curl.h>

namespace osquery {
namespace tables {

const std::string col_target_name = "target_name";
const std::string col_metric = "metric_name";
const std::string col_value = "metric_value";
const std::string col_timestamp = "timestamp_ms";

struct retData {
  int size;
  std::string content;
  std::chrono::milliseconds timestampMS;
};

typedef std::map<std::string, retData*> scrapeResults;

class PrometheusMetrics {
 public:
  PrometheusMetrics(std::vector<std::string> urls, long timeoutDurationS = 1L)
      : urls_(urls),
        multiHandle_(curl_multi_init()),
        timeoutDurtionS_(timeoutDurationS) {}

  virtual ~PrometheusMetrics() {
    curl_multi_cleanup(multiHandle_);
  }

  QueryData& queryPrometheusTargets();

 protected:
  virtual std::map<std::string, retData*> scrapeTargets();

 private:
  std::vector<std::string> urls_;
  QueryData rows_;
  CURLM* multiHandle_;
  long timeoutDurtionS_;

  void parseScrapeResults(std::map<std::string, retData*>& scrapeResults);
};
}
}
