/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <map>
#include <string>

#include <osquery/config/config.h>
#include <osquery/events/eventsubscriber.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/tables/yara/yara_utils.h>

/// The file change event publishers are slightly different in OS X and Linux.
#ifdef __APPLE__
#include <osquery/events/darwin/fsevents.h>
#elif __linux__
#include <osquery/events/linux/inotify.h>
#endif

#ifdef CONCAT
#undef CONCAT
#endif
#include <yara.h>

namespace osquery {

/// The file change event publishers are slightly different in OS X and Linux.
#ifdef __APPLE__
using FileEventSubscriber = EventSubscriber<FSEventsEventPublisher>;
using FileEventContextRef = FSEventsEventContextRef;
using FileSubscriptionContextRef = FSEventsSubscriptionContextRef;
#define FILE_CHANGE_MASK                                                       \
  kFSEventStreamEventFlagItemCreated | kFSEventStreamEventFlagItemModified |   \
      kFSEventStreamEventFlagItemRenamed
#elif __linux__
using FileEventSubscriber = EventSubscriber<INotifyEventPublisher>;
using FileEventContextRef = INotifyEventContextRef;
using FileSubscriptionContextRef = INotifySubscriptionContextRef;
#define FILE_CHANGE_MASK                                                       \
  ((IN_CREATE) | (IN_CLOSE_WRITE) | (IN_MODIFY) | (IN_MOVED_TO))
#endif

/**
 * @brief Track YARA matches to files.
 */
class YARAEventSubscriber : public FileEventSubscriber {
 public:
  Status init() override {
    return Status(0);
  }

  void configure() override;

 private:
  /**
   * @brief This exports a single Callback for FSEventsEventPublisher events.
   *
   * @param ec The Callback type receives an EventContextRef substruct
   * for the FSEventsEventPublisher declared in this EventSubscriber subclass.
   *
   * @return Status
   */
  Status Callback(const FileEventContextRef& ec,
                  const FileSubscriptionContextRef& sc);
};

/**
 * @brief Each EventSubscriber must register itself so the init method is
 * called.
 *
 * This registers YARAEventSubscriber into the osquery EventSubscriber
 * pseudo-plugin registry.
 */
REGISTER(YARAEventSubscriber, "event_subscriber", "yara_events");

void YARAEventSubscriber::configure() {
  removeSubscriptions();

  // There is a special yara parser that tracks the related top-level keys.
  auto plugin = Config::getParser("yara");
  if (plugin == nullptr || plugin.get() == nullptr) {
    return;
  }

  // Bail if there is no configured set of opt-in paths for yara.
  const auto& yara_config = plugin->getData().doc();
  if (!yara_config.HasMember("file_paths") ||
      !yara_config["file_paths"].IsObject()) {
    return;
  }

  // Collect the set of paths, we are mostly concerned with the categories.
  // But the subscriber must duplicate the set of subscriptions such that the
  // publisher's 'fire'-matching logic routes related events to our callback.
  std::map<std::string, std::vector<std::string>> file_map;
  Config::get().files([&file_map](const std::string& category,
                                  const std::vector<std::string>& files) {
    file_map[category] = files;
  });

  // For each category within yara's file_paths, add a subscription to the
  // corresponding set of paths.
  const auto& yara_paths = yara_config["file_paths"];
  for (const auto& yara_path_element : yara_paths.GetObject()) {
    std::string category = yara_path_element.name.GetString();
    // Subscribe to each file for the given key (category).
    if (file_map.count(category) == 0) {
      VLOG(1) << "Key in YARA file_paths not found in file_paths: " << category;
      continue;
    }

    for (const auto& file : file_map.at(category)) {
      VLOG(1) << "Added YARA listener to: " << file;
      auto sc = createSubscriptionContext();
      sc->recursive = 0;
      sc->path = file;
      sc->mask = FILE_CHANGE_MASK;
      sc->category = category;
      subscribe(&YARAEventSubscriber::Callback, sc);
    }
  }
}

Status YARAEventSubscriber::Callback(const FileEventContextRef& ec,
                                     const FileSubscriptionContextRef& sc) {
  if (ec->action != "UPDATED" && ec->action != "CREATED" &&
      ec->action != "MOVED_TO") {
    return Status(1, "Invalid action");
  }

  Row r;
  r["action"] = ec->action;
  r["target_path"] = ec->path;
  r["category"] = sc->category;

  // Only FSEvents transactions updates (inotify is a no-op).
  r["transaction_id"] = INTEGER(ec->transaction_id);

  // These are default values, to be updated in YARACallback.
  r["count"] = INTEGER(0);
  r["matches"] = std::string("");
  r["strings"] = std::string("");
  r["tags"] = std::string("");

  auto parser = Config::getParser("yara");
  if (parser == nullptr || parser.get() == nullptr) {
    return Status(1, "ConfigParser unknown.");
  }

  std::shared_ptr<YARAConfigParserPlugin> yaraParser;
  try {
    yaraParser = std::dynamic_pointer_cast<YARAConfigParserPlugin>(parser);
  } catch (const std::bad_cast&) {
    return Status(1, "Error casting yara config parser plugin");
  }
  if (yaraParser == nullptr || yaraParser.get() == nullptr) {
    return Status(1, "Yara parser unknown.");
  }

  const auto& rules = yaraParser->rules();

  // Use the category as a lookup into the yara file_paths. The value will be
  // a list of signature groups to scan with.
  auto category = r.at("category");
  const auto& yara_config = parser->getData().doc();
  const auto& yara_paths = yara_config["file_paths"];
  const auto group_iter = yara_paths.FindMember(category);
  if (group_iter != yara_paths.MemberEnd()) {
    for (const auto& rule : group_iter->value.GetArray()) {
      std::string group = rule.GetString();

      auto rule_it = rules.find(group);

      if (rule_it == rules.end()) {
        VLOG(1) << "Yara rules group " + group + " not found, skipping it";

        continue;
      }

      int result = yr_rules_scan_file(rule_it->second.get(),
                                      ec->path.c_str(),
                                      SCAN_FLAGS_FAST_MODE,
                                      YARACallback,
                                      (void*)&r,
                                      0);

      if (result != ERROR_SUCCESS) {
        return Status(1, "YARA error: " + std::to_string(result));
      }
    }
  }

  if (ec->action != "" && !r.at("matches").empty()) {
    add(r);
  }

  return Status::success();
}
} // namespace osquery
