/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "logger.h"

#include <osquery/utils/json/json.h>

namespace rj = rapidjson;

namespace osquery {

namespace {

void deserializeIntermediateLog(const PluginRequest& request,
                                       std::vector<StatusLogLine>& log) {
  if (request.count("log") == 0) {
    return;
  }

  rj::Document doc;
  if (doc.Parse(request.at("log").c_str()).HasParseError()) {
    return;
  }

  for (auto& line : doc.GetArray()) {
    log.push_back({
        static_cast<StatusLogSeverity>(line["s"].GetInt()),
        line["f"].GetString(),
        line["i"].GetUint64(),
        line["m"].GetString(),
        line["c"].GetString(),
        line["u"].GetUint64(),
        line["h"].GetString(),
    });
  }
}

}

Status LoggerPlugin::call(const PluginRequest& request,
                          PluginResponse& response) {
  std::vector<StatusLogLine> intermediate_logs;
  if (request.count("string") > 0) {
    return this->logString(request.at("string"));
  } else if (request.count("snapshot") > 0) {
    return this->logSnapshot(request.at("snapshot"));
  } else if (request.count("init") > 0) {
    deserializeIntermediateLog(request, intermediate_logs);
    this->setProcessName(request.at("init"));
    this->init(this->name(), intermediate_logs);
    return Status(0);
  } else if (request.count("status") > 0) {
    deserializeIntermediateLog(request, intermediate_logs);
    return this->logStatus(intermediate_logs);
  } else if (request.count("event") > 0) {
    return this->logEvent(request.at("event"));
  } else if (request.count("action") && request.at("action") == "features") {
    size_t features = 0;
    features |= (usesLogStatus()) ? LOGGER_FEATURE_LOGSTATUS : 0;
    features |= (usesLogEvent()) ? LOGGER_FEATURE_LOGEVENT : 0;
    return Status(static_cast<int>(features));
  } else {
    return Status(1, "Unsupported call to logger plugin");
  }
}

} // namespace osquery
