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

namespace osquery {
namespace tables {

void reportAugeasError(const augeas* aug) {
  const char* error_message = aug_error_message(const_cast<augeas*>(aug));
  VLOG(1) << "An error has occurred while trying to query augeas: "
          << error_message;
}

void getSpanInfo(augeas* aug,
                 Row& r,
                 QueryContext& context,
                 const std::string& path) {
  auto index = context.getCache(path);
  const auto cached_filename = index.find("filename");
  if (cached_filename != index.end()) {
    r["filename"] = cached_filename->second;
  } else {
    char* filename = nullptr;
    // Unused for now
    unsigned int label_start = 0;
    unsigned int label_end = 0;
    unsigned int value_start = 0;
    unsigned int value_end = 0;
    unsigned int span_start = 0;
    unsigned int span_end = 0;

    int result = aug_span(aug,
                          path.c_str(),
                          &filename,
                          &label_start,
                          &label_end,
                          &value_start,
                          &value_end,
                          &span_start,
                          &span_end);
    if (result == 0 && filename != nullptr) {
      r["filename"] = filename;
      context.setCache(path, "filename", filename);
      // aug_span() allocates the filename and expects the caller to free it.
      free(filename);
    }
  }
}

void getLabelInfo(const augeas* aug,
                  Row& r,
                  QueryContext& context,
                  const std::string& path) {
  auto index = context.getCache(path);
  const auto cached_label = index.find("label");
  if (cached_label != index.end()) {
    r["label"] = cached_label->second;
  } else {
    const char* label = nullptr;
    int result = aug_label(aug, path.c_str(), &label);
    if (result == 1 && label != nullptr) {
      r["label"] = label;
      context.setCache(path, "label", label);

      // Do not call free() on label. Augeas needs it.
    }
  }
}

void matchAgueasPattern(QueryData& results,
                        QueryContext& context,
                        augeas* aug,
                        const std::string& pattern) {
  char** matches = nullptr;
  int len = aug_match(aug, pattern.c_str(), &matches);

  // Handle matching errors.
  if (matches == nullptr) {
    return;
  } else if (len < 0) {
    reportAugeasError(aug);
    return;
  }

  for (int i = 0; i < len; i++) {
    Row r;
    if (matches[i] == nullptr) {
      continue;
    }

    // The caller is responsible for the matching memory.
    std::string path(static_cast<const char*>(matches[i]));
    free(matches[i]);

    const char* value = nullptr;
    int result = aug_get(aug, path.c_str(), &value);
    if (result == 1) {
      r["path"] = path;

      if (value != nullptr) {
        r["value"] = value;
      }

      getSpanInfo(aug, r, context, path);

      getLabelInfo(aug, r, context, path);

      results.push_back(r);
    } else if (result < 1) {
      reportAugeasError(aug);
    }
  }

  // aug_match() allocates the matches array and expects the
  // caller to free it
  free(matches);
}

QueryData genAugeas(QueryContext& context) {
  QueryData results;

  augeas* aug = aug_init(nullptr, nullptr, AUG_NO_ERR_CLOSE | AUG_ENABLE_SPAN);

  // Handle initialization errors.
  if (aug == nullptr) {
    VLOG(1) << "An error has occurred while trying to initialize augeas";
    return results;
  } else if (aug_error(aug) != AUG_NOERROR) {
    // Do not use aug_error_details() here since augeas is not fully
    // initialized.
    VLOG(1) << "An error has occurred while trying to initialize augeas: "
            << aug_error_message(aug);
    aug_close(aug);
    return results;
  }

  if (context.hasConstraint("path", EQUALS)) {
    auto paths = context.constraints["path"].getAll(EQUALS);
    auto pattern = boost::algorithm::join(paths, "|");
    matchAgueasPattern(results, context, aug, pattern);
  } else {
    matchAgueasPattern(results, context, aug, "/files//*");
  }

  aug_close(aug);
  return results;
}
}
}
