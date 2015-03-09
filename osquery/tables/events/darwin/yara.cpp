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

#include <yara.h>

#include "osquery/events/darwin/fsevents.h"

namespace osquery {
namespace tables {

/**
 * @brief Track YARA matches to files.
 */
class YARAEventSubscriber : public EventSubscriber<FSEventsEventPublisher> {
  DECLARE_SUBSCRIBER("yara");

 public:
  void init();

 private:
  // XXX: Is there a better way to say "I'm not ready to receive events"?
  bool ready = false;
  std::map<std::string, YR_RULES *> rules;

  /**
   * @brief This exports a single Callback for FSEventsEventPublisher events.
   *
   * @param ec The Callback type receives an EventContextRef substruct
   * for the FSEventsEventPublisher declared in this EventSubscriber subclass.
   *
   * @return Status
   */
  Status Callback(const FSEventsEventContextRef& ec, const void* user_data);
};

/**
 * @brief Each EventSubscriber must register itself so the init method is
 * called.
 *
 * This registers YARAEventSubscriber into the osquery EventSubscriber
 * pseudo-plugin registry.
 */
REGISTER(YARAEventSubscriber, "event_subscriber", "yara");

/**
 * The callback used when there are compilation problems in the rules.
 */
void YARACompilerCallback(int error_level,
                          const char* file_name,
                          int line_number,
                          const char* message,
                          void* user_data) {
  if (error_level == YARA_ERROR_LEVEL_ERROR) {
    VLOG(1) << file_name << "(" << line_number << "): error: " << message;
  }
  else {
    VLOG(1) << file_name << "(" << line_number << "): warning: " << message;
  }
}

void YARAEventSubscriber::init() {
  YR_COMPILER *compiler = nullptr;
  bool compiled;

  int result = yr_initialize();
  if (result != ERROR_SUCCESS) {
    VLOG(1) << "Unable to initalize YARA.";
    return;
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
      subscribe(&YARAEventSubscriber::Callback, mc, (void*)(&element.first));
    }

    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
      VLOG(1) << "Could not create compiler.";
      return;
    }

    yr_compiler_set_callback(compiler, YARACompilerCallback, NULL);

    // Attempt to compile the rules for this category.
    for (const auto& rule : element.second) {
      compiled = false;
      YR_RULES *tmp_rules;

      // First attempt to load the file, in case it is saved (pre-compiled)
      // rules. Sadly there is no way to load multiple compiled rules in
      // succession. This means that:
      //
      // saved1, saved2 
      //
      // results in saved2 being the only file used.
      //
      // Also, mixing source and saved rules results in the saved rules being
      // overridden by the combination of the source rules once compiled, e.g.:
      //
      // file1, saved1 
      //
      // result in file1 being the only file used.
      //
      // If you want to use saved rule files you must have them all in a single
      // file. This is easy to accomplish with yarac(1).
      result = yr_rules_load(rule.c_str(), &tmp_rules);
      if (result != ERROR_SUCCESS && result != ERROR_INVALID_FILE) {
        VLOG(1) << "Error loading YARA rules.";
        yr_compiler_destroy(compiler);
        return;
      } else if (result == ERROR_SUCCESS) {
        // If there are already rules there, destroy them and put new ones in.
        if (rules.count(element.first) > 0) {
          yr_rules_destroy(rules[element.first]);
        }
        rules[element.first] = tmp_rules;
      } else {
        compiled = true;
        // Try to compile the rules.
        FILE *rule_file = fopen(rule.c_str(), "r");

        if (rule_file == nullptr) {
          VLOG(1) << "Could not open file: " << rule;
          yr_compiler_destroy(compiler);
          return;
        }

        int errors = yr_compiler_add_file(compiler,
                                          rule_file,
                                          NULL,
                                          rule.c_str());

        fclose(rule_file);
        rule_file = nullptr;

        if (errors > 0) {
          yr_compiler_destroy(compiler);
          return;
        }
      }
    }

    if (compiled) {
      // All the rules for this category have been compiled, save them in
      // the map.
      result = yr_compiler_get_rules(compiler, &rules[element.first]);

      if (result != ERROR_SUCCESS) {
        VLOG(1) << "Insufficent memory to get rules.";
        yr_compiler_destroy(compiler);
        return;
      }
    }

    if (compiler != nullptr) {
      yr_compiler_destroy(compiler);
      compiler = nullptr;
    }
  }

  ready = true;
}

/**
 * This is the YARA callback. Used to store matching rules in the row which is
 * passed in as user_data.
 */
int YARACallback(int message, void *message_data, void *user_data) {
  if (message == CALLBACK_MSG_RULE_MATCHING) {
    Row *r = (Row *) user_data;
    YR_RULE *rule = (YR_RULE *) message_data;
    if ((*r)["matches"].length() > 0) {
      (*r)["matches"] += "," + std::string(rule->identifier);
    } else {
      (*r)["matches"] = std::string(rule->identifier);
    }
    (*r)["count"] = INTEGER(std::stoi((*r)["count"]) + 1);
  }

  return CALLBACK_CONTINUE;
}

Status YARAEventSubscriber::Callback(const FSEventsEventContextRef& ec,
                                     const void* user_data) {
  // Don't scan if there was an error with the init or if the file is deleted.
  if (ready == false || ec->action == "DELETED") {
    return Status(0, "OK");
  }

  Row r;
  r["action"] = ec->action;
  r["time"] = ec->time_string;
  r["target_path"] = ec->path;
  if (user_data != nullptr) {
    r["category"] = *(std::string*)user_data;
  } else {
    r["category"] = "Undefined";
  }
  r["transaction_id"] = INTEGER(ec->fsevent_id);

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
    return Status(1, "YARA error: " + std::to_string(result));
  }

  if (ec->action != "") {
    add(r, ec->time);
  }
  return Status(0, "OK");
}
}
}
