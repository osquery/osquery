/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <osquery/config.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include <osquery/tables/applications/posix/prometheus_metrics.h>
#include <osquery/tables/applications/posix/prometheus_metrics_utils.h>

namespace osquery {
namespace tables {

#ifdef _WIN32
inline void wait(int x) {
  Sleep(x);
}
#else
/* Portable sleep for platforms other than Windows. */
inline void wait(int x) {
  struct timeval wait = {0, (x)*1000};
  (void)select(0, NULL, NULL, NULL, &wait);
}
#endif

size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp) {
  size_t realSize = size * nmemb;
  struct retData* payload = (struct retData*)userp;

  payload->timestampMS = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch());

  char* cContents = (char*)contents;
  for (size_t i = 0; i < realSize; i++) {
    payload->content.push_back(cContents[i]);
  }

  payload->size += realSize;

  return realSize;
}

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
  std::vector<CURL*> handles;
  int stillRunning, repeat0fd;

  // create a separate handle per target url
  for (auto const& url : urls_) {
    CURL* handle = curl_easy_init();
    CURLcode code = CURLE_FAILED_INIT;
    retData* ret = new retData;

    if (CURLE_OK ==
            (code = curl_easy_setopt(handle, CURLOPT_URL, url.c_str())) &&
        CURLE_OK == (code = curl_easy_setopt(
                         handle, CURLOPT_WRITEFUNCTION, &writeCallback)) &&
        CURLE_OK == (code = curl_easy_setopt(handle, CURLOPT_WRITEDATA, ret)) &&
        CURLE_OK == (code = curl_easy_setopt(
                         handle, CURLOPT_TIMEOUT, timeoutDurtionS_))) {
      handles.push_back(handle);
      curl_multi_add_handle(multiHandle_, handle);
      results[url] = ret;

    } else {
      LOG(ERROR) << "failed on intialization of curl handle for '" << url
                 << "' with error: " << curl_easy_strerror(code);
      curl_easy_cleanup(handle);
    }
  }

  // send async requests and watch for changes
  // initiate multiperform action
  curl_multi_perform(multiHandle_, &stillRunning);

  do {
    CURLMcode status;
    int numfds;

    status = curl_multi_wait(
        multiHandle_, NULL, 0, timeoutDurtionS_ * 1000, &numfds);
    if (status != CURLM_OK) {
      // log error
      LOG(ERROR) << "failed on curl_multi_wait: "
                 << curl_multi_strerror(status);
      break;
    }
    /* From libcurl docs:
      'numfds' being zero means either a timeout or no file descriptors to
      wait for. Try timeout on first occurrence, then assume no file
      descriptors and no file descriptors to wait for means wait for 100
      milliseconds. */
    if (!numfds) {
      repeat0fd++;

      if (repeat0fd > 1) {
        wait(100);
      }

    } else {
      repeat0fd = 0;
    }

    curl_multi_perform(multiHandle_, &stillRunning);

  } while (stillRunning);

  // clean up handles
  for (auto& handle : handles) {
    curl_multi_remove_handle(multiHandle_, handle);
    curl_easy_cleanup(handle);
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
