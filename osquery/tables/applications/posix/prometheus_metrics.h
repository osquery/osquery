/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */
#pragma once

#include <chrono>
#include <map>
#include <string>
#include <vector>

#include <osquery/tables.h>

namespace osquery {
namespace tables {

const std::string kColTargetName {"target_name"};
const std::string kColMetric {"metric_name"};
const std::string kColValue {"metric_value"};
const std::string kColTimeStamp {"timestamp_ms"};

struct PrometheusResponseData {
  std::string content;
  std::chrono::milliseconds timestampMS;
};

/**
 * @brief parse raw payload returned by scraped targets into QueryData.
 *
 * @param scrapeResults map where the key is the target url scraped and
 * value is the struct PrometheusResponseData of the corresponding target.
 *
 */
void parseScrapeResults(
    const std::map<std::string, PrometheusResponseData>& scrapeResults,
    QueryData& rows);

/**
 * @brief Scrapes the Prometheus targets and returns response payload and
 * timestamp.
 *
 * @param scrapeResults map where the key is the target url to be scraped and
 * value is the struct PrometheusResponseData where payload and timestamp are to
 * be written to.
 *
 * @param int for request timeout in seconds.
 */
void scrapeTargets(std::map<std::string, PrometheusResponseData>& scrapeResults,
                   size_t timeoutS = 1);
}
}
