/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "osquery/tables/system/linux/special_xattr_decoder.h"
#include <errno.h>

namespace osquery {
namespace {
using cap_t = void*;

extern "C" cap_t cap_get_file(const char*);
extern "C" char* cap_to_text(cap_t, ssize_t*);
extern "C" int cap_free(void*);
} // namespace

const std::string kSecurityCapabilityXattrName = "security.capability";

bool isSpecialExtendedAttribute(const std::string& name) {
  return (name == kSecurityCapabilityXattrName);
}

bool decodeSpecialExtendedAttribute(ExtendedAttributes& output,
                                    const std::string& path,
                                    const std::string& name) {
  output.clear();

  if (name != kSecurityCapabilityXattrName) {
    return false;
  }

  errno = 0;
  auto capabilities = cap_get_file(path.data());
  if (capabilities == nullptr) {
    if (errno == ENODATA) {
      return true;
    }

    return false;
  }

  auto description = cap_to_text(capabilities, nullptr);
  cap_free(capabilities);

  if (description == nullptr) {
    return false;
  }

  // libcap prefixes descriptions with '= '
  output.push_back(std::make_pair(name, description + 2));
  cap_free(description);

  return true;
}
} // namespace osquery
