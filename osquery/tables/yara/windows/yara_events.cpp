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
#include <osquery/events/windows/ntfs_event_publisher.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/tables/events/windows/ntfs_journal_events.h>
#include <osquery/tables/yara/yara_utils.h>

#include <yara.h>

namespace osquery {

using FileEventSubscriber = NTFSEventSubscriber;
using FileEventContextRef = NTFSEventContextRef;
using FileSubscriptionContextRef = NTFSEventSubscriptionContextRef;

/**
 * @brief Track YARA matches to files.
 */
class YARAEventSubscriber : public FileEventSubscriber {
 public:
  Status init() override {
    return Status::success();
  }

  void configure() override;

 private:
  /**
   * @brief This exports a single Callback for FSEventsEventPublisher events.
   *
   * @param event The Callback type receives an EventContextRef substruct
   * for the FSEventsEventPublisher declared in this EventSubscriber subclass.
   *
   * @return Status
   */
  Status Callback(const FileEventContextRef& event,
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

  const auto& json = Config::getParser("file_paths")->getData();
  const auto& json_document = json.doc();

  // Collect the set of paths, we are mostly concerned with the categories.
  // But the subscriber must duplicate the set of subscriptions such that the
  // publisher's 'fire'-matching logic routes related events to our callback.
  std::map<std::string, std::vector<std::string>> file_map;
  Config::get().files(
      [this, &file_map, &json_document](const std::string& category,
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

    StringList include_path_list = {};
    for (const auto& file : file_map.at(category)) {
      // NOTE(woodruffw): This will remove nonexistent paths, even if
      // they aren't patterns. For example, C:\foo\bar won't
      // be monitored if it doesn't already exist at table/event
      // creation time. Is that what we want?
      resolveFilePattern(file, include_path_list);
    }

    StringList exclude_path_list = {};
    if (json_document.HasMember("exclude_paths") &&
        json_document["exclude_paths"][category].IsArray()) {
      const auto& excludes =
          json_document["exclude_paths"][category].GetArray();
      for (const auto& exclude : excludes) {
        if (!exclude.IsString()) {
          continue;
        }
        resolveFilePattern(exclude.GetString(), exclude_path_list);
      }
    }

    auto sc = createSubscriptionContext();
    sc->category = category;
    processConfiguration(sc, {}, include_path_list, exclude_path_list);
    VLOG(1) << "Added YARA listener for category: " << category;
    subscribe(&YARAEventSubscriber::Callback, sc);
  }
}

Status YARAEventSubscriber::Callback(const FileEventContextRef& ec,
                                     const FileSubscriptionContextRef& sc) {
  std::vector<Row> rows;
  for (const auto& event : ec->event_list) {
    if (!shouldEmit(sc, event)) {
      continue;
    }

    Row r;
    auto action_description_it = kNTFSEventToStringMap.find(event.type);
    assert(action_description_it != kNTFSEventToStringMap.end());

    r["action"] = SQL_TEXT(action_description_it->second);
    r["target_path"] = event.path;
    r["category"] = sc->category;

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
                                        event.path.c_str(),
                                        SCAN_FLAGS_FAST_MODE,
                                        YARACallback,
                                        (void*)&r,
                                        0);

        if (result != ERROR_SUCCESS) {
          return Status(1, "YARA error: " + std::to_string(result));
        }
      }
    }

    if (r["action"] != "" && !r.at("matches").empty()) {
      rows.push_back(r);
    }
  }

  if (!rows.empty()) {
    addBatch(rows);
  }

  return Status::success();
}
} // namespace osquery
