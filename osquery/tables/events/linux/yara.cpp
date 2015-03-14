/*
 *  Copyright (c) 2015, Wesley Shields
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <map>
#include <string>

#include <osquery/config.h>
#include <osquery/logger.h>

#define NOMINMAX
#include <yara.h>
#undef NOMINMAX

#include "osquery/events/linux/inotify.h"
#include "osquery/tables/events/yara_utils.h"

namespace osquery {
namespace tables {

/**
 * @brief Track YARA matches to files.
 */
class YARAEventSubscriber : public EventSubscriber<INotifyEventPublisher> {
  DECLARE_SUBSCRIBER("yara");

 public:
  Status init();

 private:
  std::map<std::string, YR_RULES *> rules;

  /**
   * @brief This exports a single Callback for INotifyEventPublisher
   * events.
   *
   * @param ec The Callback type receives an EventContextRef substruct
   * for the INotifyEventPublisher declared in this EventSubscriber subclass.
   *
   * @return Status
   */
  Status Callback(const INotifyEventContextRef& ec, const void* user_data);
};

/**
 * @brief Each EventSubscriber must register itself so the init method is
 * called.
 *
 * This registers YARAEventSubscriber into the osquery EventSubscriber
 * pseudo-plugin registry.
 */
REGISTER(YARAEventSubscriber, "event_subscriber", "yara");

Status YARAEventSubscriber::init() {
  Status status;

  int result = yr_initialize();
  if (result != ERROR_SUCCESS) {
    LOG(WARNING) << "Unable to initalize YARA (" << result << ").";
    return Status(1, "Unable to initalize YARA.");
  }

  const auto& yara_map = Config::getYARAFiles();
  const auto& file_map = Config::getWatchedFiles();

  // yara_map has a key of the category and a vector of rule files to load.
  // file_map has a key of the category and a vector of files to watch. Use
  // yara_map to get the category and subscribe to each file in file_map
  // with that category. Then load each YARA rule file from yara_map.
  for (const auto& element : yara_map) {
    // Subscribe to each file for the given key (category).
    for (const auto& file : file_map.find(element.first)->second) {
      VLOG(1) << "Added YARA listener to: " << file;
      auto mc = createSubscriptionContext();
      mc->path = file;
      mc->recursive = true;
      mc->mask = IN_CREATE | IN_CLOSE_WRITE | IN_MODIFY;
      subscribe(&YARAEventSubscriber::Callback, mc, (void*)(&element.first));
    }

    // Attempt to compile the rules for this category.
    status = handleRuleFiles(element.first, element.second, &rules);
    if (!status.ok()) {
      VLOG(1) << "Error: " << status.getMessage();
      return status;
    }
  }

  return Status(0, "OK");
}

Status YARAEventSubscriber::Callback(const INotifyEventContextRef& ec,
                                     const void* user_data) {
  Row r;
  r["action"] = ec->action;
  r["time"] = ec->time_string;
  r["target_path"] = ec->path;
  if (user_data != nullptr) {
    r["category"] = *(std::string*)user_data;
  } else {
    r["category"] = "Undefined";
  }
  r["transaction_id"] = INTEGER(ec->event->cookie);

  // These are default values, to be updated in YARACallback.
  r["count"] = INTEGER(0);
  r["matches"] = std::string("");

  int result = yr_rules_scan_file(rules[*(std::string*)user_data],
                                  ec->path.c_str(),
                                  SCAN_FLAGS_FAST_MODE,
                                  YARACallback,
                                  (void*) &r,
                                  0);

  if (result != ERROR_SUCCESS) {
    VLOG(1) << "ERROR: " << std::to_string(result);
    return Status(1, "YARA error: " + std::to_string(result));
  }

  if (ec->action != "") {
    add(r, ec->time);
  }
  return Status(0, "OK");
}
}
}
