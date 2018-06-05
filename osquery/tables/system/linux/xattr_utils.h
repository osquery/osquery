/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

namespace osquery {
namespace {
using cap_t = void*;
extern "C" cap_t cap_get_file(const char*);
extern "C" char* cap_to_text(cap_t, ssize_t*);
extern "C" int cap_free(void*);
} // namespace

Status readSpecialExtendedAttribute(
    std::unordered_map<std::string, std::string>& output,
    const std::string& path,
    const std::string& name) {
  output.clear();

  if (name != "security.capability") {
    return Status(0, "OK");
  }

  errno = 0;
  auto capabilities = cap_get_file(path.data());
  if (capabilities == nullptr) {
    if (errno == ENODATA) {
      return Status(0, "OK");
    }

    return Status(
        1, "Failed to read the capabilities for the following file: " + path);
  }

  auto description = cap_to_text(capabilities, nullptr);
  cap_free(capabilities);

  if (description == nullptr) {
    return Status(
        1, "Failed to parse the capabilities for the following file: " + path);
  }

  output.insert(
      {name, description + 2}); // libcap prefixes descriptions with '= '
  cap_free(description);

  return Status(0, "OK");
}
} // namespace osquery
