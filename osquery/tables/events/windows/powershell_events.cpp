/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <cmath>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/registry_factory.h>

#include "osquery/config/parsers/feature_vectors.h"
#include "osquery/core/conversions.h"
#include "osquery/core/json.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/events/windows/windows_event_log.h"
#include "osquery/filesystem/fileops.h"

namespace pt = boost::property_tree;

namespace osquery {

const std::string kPowershellDomain{"powershell_script_block_logs"};
const std::string kScriptBlockPrefix{"script_block."};
const std::string kScriptBlocksReceivedSuffix{".blocks_received"};
const std::wstring kPowershellEventsChannel{
    L"microsoft-windows-powershell/operational"};

const int kScriptBlockLoggingEid{4104};
const int kCharFreqVectorLen{255};

void parseTree(const pt::ptree& tree, std::map<std::string, std::string>& res);

class PowershellEventSubscriber
    : public EventSubscriber<WindowsEventLogEventPublisher> {
 public:
  Status init() override {
    // Before starting our subscription, purge any residual db entries as it's
    // unlikely we'll finish re-assmebling them
    std::vector<std::string> keys;
    scanDatabaseKeys(kEvents, keys, kScriptBlockPrefix);
    for (const auto& k : keys) {
      auto s = deleteDatabaseValue(kEvents, k);
      if (!s.ok()) {
        VLOG(1) << "Failed to delete stale script block from the database "
                << k;
      }
    }

    auto wc = createSubscriptionContext();
    wc->sources.insert(kPowershellEventsChannel);

    subscribe(&PowershellEventSubscriber::Callback, wc);
    return Status();
  }

  Status Callback(const ECRef& ec, const SCRef& sc);

  void addScriptResult(Row& results);
};

REGISTER(PowershellEventSubscriber, "event_subscriber", "powershell_events");

inline double cosineSimilarity(std::vector<double>& script_freqs,
                               std::vector<double>& global_freqs) {
  auto dot = 0.0;
  auto mag1 = 0.0;
  auto mag2 = 0.0;

  for (size_t i = 0; i < global_freqs.size(); i++) {
    dot += script_freqs[i] * global_freqs[i];
    mag1 += script_freqs[i] * script_freqs[i];
    mag2 += global_freqs[i] * global_freqs[i];
  }

  mag1 = sqrt(mag1);
  mag2 = sqrt(mag2);

  return dot / (mag1 * mag2);
}

void PowershellEventSubscriber::addScriptResult(Row& results) {
  Row r;
  r["time"] = results["time"];
  r["datetime"] = results["datetime"];
  r["script_block_id"] = results["ScriptBlockId"];
  r["script_block_count"] = INTEGER(results["MessageTotal"]);
  r["script_name"] = results["Name"];
  r["script_path"] = results["Path"];
  r["script_text"] = results["ScriptBlockText"];

  // Grab the feature vectors from the configuration
  auto parser = Config::getParser(kFeatureVectorsRootKey);
  if (parser == nullptr) {
    VLOG(1) << "Failed to get configured feature vectors";
    add(r);
    return;
  }

  // Get the reassembled powershell scripts character frequency vector
  std::vector<double> freqs(kCharFreqVectorLen, 0.0);
  for (const auto chr : r["script_text"]) {
    if (chr < kCharFreqVectorLen) {
      freqs[chr] += 1.0 / r["script_text"].length();
    }
  }

  const auto& cf =
      parser->getData().doc()["feature_vectors"]["character_frequencies"];
  if (cf.Empty() || cf.Size() != kCharFreqVectorLen) {
    VLOG(1) << "Invalid character frequency map found, using default values";
    add(r);
    return;
  }

  std::vector<double> cfg_freqs(kCharFreqVectorLen, 0.0);
  for (unsigned int i = 0; i < cf.Size(); i++) {
    cfg_freqs[i] = cf[i].GetDouble();
  }
  r["cosine_similarity"] = DOUBLE(cosineSimilarity(freqs, cfg_freqs));
  add(r);
}

Status PowershellEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  // For script block logging we only care about events with script blocks
  auto eid = ec->eventRecord.get("Event.System.EventID", -1);
  if (eid != kScriptBlockLoggingEid) {
    return Status();
  }

  Row results;
  for (const auto& node : ec->eventRecord.get_child("Event", pt::ptree())) {
    if (node.first == "System" || node.first == "<xmlattr>") {
      continue;
    }
    // #4357: This should make use of RapidJSON
    parseTree(node.second, results);
  }

  FILETIME etime;
  GetSystemTimeAsFileTime(&etime);
  results["time"] = BIGINT(filetimeToUnixtime(etime));
  results["datetime"] =
      ec->eventRecord.get("Event.System.TimeCreated.<xmlattr>.SystemTime", "");

  // If there's only one script block no reassembly is needed
  if (results["MessageTotal"] == "1") {
    addScriptResult(results);
    return Status();
  }

  // Add the script content to the DB for later reassembly
  auto s = setDatabaseValue(kEvents,
                            kScriptBlockPrefix + results["ScriptBlockId"] +
                                "." + results["MessageNumber"],
                            results["ScriptBlockText"]);
  if (!s.ok()) {
    LOG(WARNING) << "Failed to add new Powershell block to database for script "
                 << results["ScriptBlockId"];
  }

  // If we expect more blocks bail out early
  if (results["MessageNumber"] != results["MessageTotal"]) {
    return Status();
  }

  // Otherwise all script blocks should be accounted for so reconstruct
  std::vector<std::string> keys;
  s = scanDatabaseKeys(
      kEvents, keys, kScriptBlockPrefix + results["ScriptBlockId"]);
  if (!s.ok()) {
    LOG(WARNING) << "Failed to look up powershell script blocks for "
                 << results["ScriptBlockId"];
    return Status(1);
  }

  std::string powershell_script{""};
  for (const auto& key : keys) {
    std::string val{""};
    s = getDatabaseValue(kEvents, key, val);
    if (!s.ok()) {
      LOG(WARNING) << "Failed to retrieve script block " << key;
      continue;
    }

    powershell_script += val;

    s = deleteDatabaseValue(kEvents, key);
    if (!s.ok()) {
      LOG(WARNING) << "Failed to delete script block key from db " << key;
    }
  }

  results["ScriptBlockText"] = powershell_script;
  addScriptResult(results);

  return Status();
}
} // namespace osquery
