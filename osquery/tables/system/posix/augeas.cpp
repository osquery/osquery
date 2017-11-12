/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <augeas.h>

#include <sstream>

#include <boost/algorithm/string/join.hpp>

#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {

/**
 * @brief Augeas lenses path.
 *
 * Directory that contains augeus lenses.
 */
#ifdef __APPLE__
FLAG(string,
     augeas_lenses,
     "/private/var/osquery/lenses",
     "Directory that contains augeas lenses files");
#else
FLAG(string,
     augeas_lenses,
     "/usr/share/osquery/lenses",
     "Directory that contains augeas lenses files");
#endif

namespace tables {

void reportAugeasError(augeas* aug) {
  const char* error_message = aug_error_message(aug);
  LOG(ERROR) << "An error has occurred while trying to query augeas: "
             << error_message;
}

void matchAugeasPattern(augeas* aug,
                        const std::string& pattern,
                        QueryData& results,
                        QueryContext& context) {
  // The caller may supply an Augeas PATH/NODE expression or filesystem path.
  // Below we formulate a Augeas pattern from a path if needed.
  int result = aug_defvar(aug, "matches", pattern.c_str());
  if (result == -1) {
    reportAugeasError(aug);
    return;
  }

  char** matches = nullptr;
  int len = aug_match(aug, "$matches", &matches);

  // Handle matching errors.
  if (matches == nullptr) {
    return;
  } else if (len < 0) {
    reportAugeasError(aug);
    return;
  }

  // Emit a row for each match.
  results.reserve(len);
  for (size_t i = 0; i < static_cast<size_t>(len); i++) {
    if (matches[i] == nullptr) {
      continue;
    }

    // The caller is responsible for the matching memory.
    std::string node(matches[i]);
    free(matches[i]);

    const char *value = nullptr, *label = nullptr;
    char* file = nullptr;
    result = aug_ns_attr(aug, "matches", i, &value, &label, &file);
    if (result == -1) {
      reportAugeasError(aug);
      return;
    }

    std::string path;
    if (file != nullptr) {
      path = file;
      path = path.substr(6);
      // The caller is responsible for the matching memory.
      free(file);
    } else {
      // The iterator is currently pointing to a folder so we extract the path
      // from the node.
      path = node.substr(6);
    }

    results.emplace_back(
        std::initializer_list<std::pair<const std::string, std::string>>{
            {"node", node},
            {"value", value == nullptr ? "" : value},
            {"path", path},
            {"label", label == nullptr ? "" : label}});
  }

  // aug_match() allocates the matches array and expects the caller to free it.
  free(matches);
}

class AugeasHandle {
 public:
  augeas* aug{nullptr};
  bool error{false};

  void initialize() {
    std::call_once(initialized, [this]() {
      this->aug = aug_init(
          nullptr, FLAGS_augeas_lenses.c_str(), AUG_NO_ERR_CLOSE | AUG_NO_LOAD);
      // Handle initialization errors.
      if (this->aug == nullptr) {
        LOG(ERROR) << "An error has occurred while trying to initialize augeas";
        error = true;
      } else if (aug_error(this->aug) != AUG_NOERROR) {
        error = true;
        // Do not use aug_error_details() here since augeas is not fully
        // initialized.
        LOG(ERROR)
            << "An error has occurred while trying to initialize augeas: "
            << aug_error_message(this->aug);
        aug_close(this->aug);
      }
    });
  }

  ~AugeasHandle() {
    aug_close(aug);
  }

 private:
  std::once_flag initialized;
};

static AugeasHandle kAugeasHandle;

QueryData genAugeas(QueryContext& context) {
  kAugeasHandle.initialize();

  if (kAugeasHandle.error == true) {
    return {};
  }

  augeas* aug = kAugeasHandle.aug;
  aug_load(aug);

  QueryData results;
  std::set<std::string> patterns;

  if (context.hasConstraint("node", EQUALS)) {
    auto nodes = context.constraints["node"].getAll(EQUALS);
    patterns.insert(nodes.begin(), nodes.end());
  }

  if (context.hasConstraint("path", EQUALS)) {
    // Allow requests via filesystem path.
    auto paths = context.constraints["path"].getAll(EQUALS);
    std::ostringstream pattern;

    for (auto path : paths) {
      pattern << "/files/" << path;
      patterns.insert(pattern.str());

      pattern.clear();
      pattern.str(std::string());

      pattern << "/files" << path << "//*";
      patterns.insert(pattern.str());

      pattern.clear();
      pattern.str(std::string());
    }
  }

  if (patterns.empty()) {
    matchAugeasPattern(aug, "/files//*", results, context);
  } else {
    matchAugeasPattern(
        aug, boost::algorithm::join(patterns, "|"), results, context);
  }

  return results;
}
}
}
