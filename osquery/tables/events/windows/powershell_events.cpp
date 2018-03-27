/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <math.h>

#include <boost/algorithm/string.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/json.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/events/windows/windows_event_log.h"
#include "osquery/filesystem/fileops.h"

namespace pt = boost::property_tree;

namespace osquery {

// TODO: Pull this from a config setting
double kGlobalFrequencies[255] = {
    0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,
    0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,
    0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,
    0.045, 1.798, 0.0,   3.111, 0.063, 0.027, 0.0,   1.336, 1.33,  0.128, 0.27,
    0.655, 1.932, 1.917, 0.432, 0.45,  0.316, 0.245, 0.133, 0.103, 0.114, 0.087,
    0.067, 0.076, 0.061, 0.483, 0.23,  0.185, 1.342, 0.196, 0.035, 0.092, 5.575,
    1.493, 3.253, 2.799, 9.818, 1.696, 1.542, 1.474, 5.123, 0.345, 0.453, 3.575,
    3.201, 5.066, 5.059, 2.875, 0.218, 5.464, 5.316, 7.471, 2.315, 0.902, 1.173,
    0.651, 1.193, 0.154, 0.621, 0.222, 0.62,  0.0,   0.538, 0.122, 0.0,   0.0,
    0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,
    0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,
    0.0,   0.0,   0.771, 0.238, 0.766, 0.0,   0.0,   0.0,   0.0,   0.0,   0.0,
    0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,
    0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,
    0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,
    0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,
    0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,
    0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,
    0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,
    0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,
    0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,
    0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,
    0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,   0.0,
    0.0,   0.0};

void parseTree(const pt::ptree& tree, std::map<std::string, std::string>& res);

class PowershellEventSubscriber
    : public EventSubscriber<WindowsEventLogEventPublisher> {
 public:
  Status init() override {
    auto wc = createSubscriptionContext();
    wc->sources.insert(
        stringToWstring("microsoft-windows-powershell/operational"));

    subscribe(&PowershellEventSubscriber::Callback, wc);
    return Status(0, "OK");
  }

  Status Callback(const ECRef& ec, const SCRef& sc);
};

REGISTER(PowershellEventSubscriber, "event_subscriber", "powershell_events");

double cosineSimCharFreq(double* freqs, size_t freqListLen) {
  double dot = 0;
  double mag1 = 0;
  double mag2 = 0;

  for (size_t i = 0; i < freqListLen; i++) {
    dot += freqs[i] * kGlobalFrequencies[i];
    mag1 += freqs[i] * freqs[i];
    mag2 += kGlobalFrequencies[i] * kGlobalFrequencies[i];
  }

  mag1 = sqrt(mag1);
  mag2 = sqrt(mag2);

  return dot / (mag1 * mag2);
}

Status PowershellEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  Row r;
  FILETIME cTime;
  GetSystemTimeAsFileTime(&cTime);
  r["time"] = BIGINT(filetimeToUnixtime(cTime));
  r["datetime"] =
      ec->eventRecord.get("Event.System.TimeCreated.<xmlattr>.SystemTime", "");

  pt::ptree jsonOut;
  std::map<std::string, std::string> results;
  std::string eventDataType;

  for (const auto& node : ec->eventRecord.get_child("Event", pt::ptree())) {
    /// We have already processed the System event data above
    if (node.first == "System" || node.first == "<xmlattr>") {
      continue;
    }
    eventDataType = node.first;
    parseTree(node.second, results);
  }

  r["script_block_id"] = results["ScriptBlockId"];
  r["message_number"] = INTEGER(results["MessageNumber"]);
  r["message_total"] = INTEGER(results["MessageTotal"]);
  r["script_name"] = results["Name"];
  r["script_path"] = results["Path"];
  std::string scriptText = results["ScriptBlockText"];
  r["script_block_text"] = scriptText;

  // TODO: Cosine similarity analysis of the script block text
  double freqs[255] = {0};
  auto getFreqs = [scriptText](const std::string& text, double* freqs) {
    for (const auto chr : text) {
      // The current data set we have is normalized to Upper :(
      unsigned char c;
      if (chr >= 97 && chr <= 122) {
        c = chr - 32;
      }
      if (c < 255) {
        freqs[c] += 1.0 / scriptText.length();
      }
    }
  };
  getFreqs(scriptText, freqs);

  r["cosine_similarity"] = DOUBLE(cosineSimCharFreq(freqs, 255));

  // TODO: Reconstruct the powershell scripts locally.

  add(r);
  return Status(0, "OK");
}
}
