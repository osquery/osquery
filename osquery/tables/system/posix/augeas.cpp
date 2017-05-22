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

#include <boost/algorithm/string/join.hpp>

#include <osquery/logger.h>
#include <osquery/tables.h>

#ifdef __APPLE__
#define LENSES_PATH "/private/var/osquery/lenses"
#else
#define LENSES_PATH "/usr/share/osquery/lenses"
#endif

namespace osquery {
namespace tables {

void reportAugeasError(augeas* aug) {
  const char* error_message = aug_error_message(aug);
  VLOG(1) << "An error has occurred while trying to query augeas: "
          << error_message;
}

std::string getSpanInfo(augeas* aug,
                        const std::string& node,
                        QueryContext& context) {
  const auto& index = context.getCache(node);
  if (index.count("filename")) {
    return index.at("filename");
  }

  char* filename = nullptr;
  // Unused for now.
  unsigned int label_start = 0;
  unsigned int label_end = 0;
  unsigned int value_start = 0;
  unsigned int value_end = 0;
  unsigned int span_start = 0;
  unsigned int span_end = 0;

  int result = aug_span(aug,
                        node.c_str(),
                        &filename,
                        &label_start,
                        &label_end,
                        &value_start,
                        &value_end,
                        &span_start,
                        &span_end);

  if (result == 0 && filename != nullptr) {
    context.setCache(node, "filename", filename);
    // aug_span() allocates the filename and expects the caller to free it.
    free(filename);
    return context.getCache(node).at("filename");
  } else {
    return "";
  }
}

std::string getLabelInfo(const augeas* aug,
                         const std::string& node,
                         QueryContext& context) {
  const auto& index = context.getCache(node);
  if (index.count("label")) {
    return index.at("label");
  }

  const char* label = nullptr;
  int result = aug_label(aug, node.c_str(), &label);
  if (result == 1 && label != nullptr) {
    context.setCache(node, "label", label);
    // Do not call free() on label. Augeas needs it.
    return context.getCache(node).at("label");
  } else {
    return "";
  }
}

void matchAugeasPattern(augeas* aug,
                        const std::string& pattern,
                        QueryData& results,
                        QueryContext& context,
                        bool use_path = false) {
  // The caller may supply an Augeas PATH/NODE expression or filesystem path.
  // Below we formulate a Augeas pattern from a path if needed.
  char** matches = nullptr;
  int len = aug_match(
      aug,
      (use_path ? ("/files/" + pattern + "|/files" + pattern + "//*").c_str()
                : pattern.c_str()),
      &matches);

  // Handle matching errors.
  if (matches == nullptr) {
    return;
  } else if (len < 0) {
    reportAugeasError(aug);
    return;
  }

  // Emit a row for each match.
  for (size_t i = 0; i < static_cast<size_t>(len); i++) {
    if (matches[i] == nullptr) {
      continue;
    }

    // The caller is responsible for the matching memory.
    std::string node(matches[i]);
    free(matches[i]);

    Row r;
    const char* value = nullptr;
    int result = aug_get(aug, node.c_str(), &value);
    if (result == 1) {
      r["node"] = node;

      if (value != nullptr) {
        r["value"] = value;
      }

      if (!use_path) {
        r["path"] = getSpanInfo(aug, node, context);
      } else {
        r["path"] = pattern;
      }

      r["label"] = getLabelInfo(aug, node, context);

      results.push_back(r);
    } else if (result < 1) {
      reportAugeasError(aug);
    }
  }

  // aug_match() allocates the matches array and expects the caller to free it.
  free(matches);
}

QueryData genAugeas(QueryContext& context) {
  augeas* aug =
      aug_init(nullptr, LENSES_PATH, AUG_NO_ERR_CLOSE | AUG_ENABLE_SPAN);

  // Handle initialization errors.
  if (aug == nullptr) {
    VLOG(1) << "An error has occurred while trying to initialize augeas";
    return {};
  } else if (aug_error(aug) != AUG_NOERROR) {
    // Do not use aug_error_details() here since augeas is not fully
    // initialized.
    VLOG(1) << "An error has occurred while trying to initialize augeas: "
            << aug_error_message(aug);
    aug_close(aug);
    return {};
  }

  QueryData results;
  if (context.hasConstraint("path", EQUALS)) {
    // Allow requests via filesystem path.
    // We will request the pattern match by path using an optional argument.
    auto paths = context.constraints["path"].getAll(EQUALS);
    for (const auto& path : paths) {
      matchAugeasPattern(aug, path, results, context, true);
    }
  } else if (context.hasConstraint("node", EQUALS)) {
    auto nodes = context.constraints["node"].getAll(EQUALS);
    auto pattern = boost::algorithm::join(nodes, "|");
    matchAugeasPattern(aug, pattern, results, context);
  } else {
    matchAugeasPattern(aug, "/files//*", results, context);
  }

  aug_close(aug);
  return results;
}
}
}
