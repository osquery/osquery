/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#ifndef __FreeBSD__

#include <string>
#include <vector>

#include <sys/xattr.h>

#include <osquery/logger.h>

#include "osquery/tables/system/posix/xattr_utils.h"

#ifdef __APPLE__
#include "osquery/tables/system/darwin/special_xattr_decoder.h"

#else
#include "osquery/tables/system/linux/special_xattr_decoder.h"
#endif

namespace osquery {
namespace {
// Compatibility wrappers for macOS
#ifdef __APPLE__
ssize_t getxattr(const char* path, const char* name, void* value, size_t size) {
  return ::getxattr(path, name, value, size, 0, 0);
}

ssize_t listxattr(const char* path, char* list, size_t size) {
  return ::listxattr(path, list, size, 0);
}

// Used by the tests in
// osquery/tables/system/posix/tests/extended_attributes_tests.cpp
int setxattr(const char* path,
             const char* name,
             const void* value,
             size_t size,
             int flags) {
  return ::setxattr(path, name, value, size, 0, flags);
}
#endif

Status getExtendedAttributeListSize(size_t& size, const std::string& path) {
  auto length = listxattr(path.data(), nullptr, 0);
  if (length == -1) {
    return Status(
        1,
        "Failed to list the extended attributes for the following path: " +
            path);
  }

  size = static_cast<size_t>(length);
  return Status(0);
}

Status getRawExtendedAttributeList(std::string& buffer,
                                   const std::string& path) {
  size_t list_size;
  auto s = getExtendedAttributeListSize(list_size, path);
  if (!s.ok()) {
    return s;
  }

  buffer.resize(list_size);
  if (buffer.size() != list_size) {
    return Status(1, "Memory allocation failure");
  }

  auto read_bytes = listxattr(path.data(), &buffer[0], buffer.size());
  if (read_bytes == -1) {
    return Status(1, "Failed to retrieve the extended attribute list");
  }

  return Status(0);
}

Status getExtendedAttributeList(std::vector<std::string>& attribute_list,
                                const std::string& path) {
  attribute_list.clear();

  std::string raw_attribute_list;
  auto s = getRawExtendedAttributeList(raw_attribute_list, path);
  if (!s.ok()) {
    return s;
  }

  size_t start_index = 0U;
  for (size_t i = 0U; i < raw_attribute_list.size(); i++) {
    if (raw_attribute_list[i] != 0) {
      continue;
    }

    auto name_length = i - start_index;
    auto name = raw_attribute_list.substr(start_index, name_length);
    start_index = i + 1;

    attribute_list.push_back(name);
  }

  return Status(0);
}

Status getExtendedAttribute(std::string& value,
                            const std::string& path,
                            const std::string& name) {
  value.clear();

  auto buffer_size = getxattr(path.data(), name.data(), nullptr, 0U);
  if (buffer_size == -1) {
    return Status(1, "Failed to get the extended attribute size");
  }

  value.resize(static_cast<size_t>(buffer_size));
  if (value.size() != static_cast<size_t>(buffer_size)) {
    return Status(1, "Memory allocation failure");
  }

  buffer_size = getxattr(path.data(), name.data(), &value[0], value.size());
  if (buffer_size == -1) {
    return Status(1, "Failed to get the extended attribute");
  }

  if (value.size() != static_cast<size_t>(buffer_size)) {
    value.resize(buffer_size);
  }

  return Status(0);
}
} // namespace

Status getExtendedAttributes(ExtendedAttributes& attributes,
                             const std::string& path) {
  std::vector<std::string> attribute_list;
  auto s = getExtendedAttributeList(attribute_list, path);
  if (!s.ok()) {
    return s;
  }

  for (const auto& attribute_name : attribute_list) {
    std::string attribute_value;
    s = getExtendedAttribute(attribute_value, path, attribute_name);
    if (!s.ok()) {
      return s;
    }

    if (isSpecialExtendedAttribute(attribute_name)) {
      ExtendedAttributes decoded_attributes;
      if (!decodeSpecialExtendedAttribute(
              decoded_attributes, path, attribute_name)) {
        VLOG(1) << "Failed to decode the special attribute '" << attribute_name
                << "' for file " << path;

        attributes.push_back(std::make_pair(attribute_name, attribute_value));

      } else {
        attributes.insert(attributes.end(),
                          decoded_attributes.begin(),
                          decoded_attributes.end());
      }

    } else {
      attributes.push_back(std::make_pair(attribute_name, attribute_value));
    }
  }

  return Status(0);
}

// Used by the tests in
// osquery/tables/system/posix/tests/extended_attributes_tests.cpp
Status setExtendedAttributes(
    const std::string& path,
    const std::unordered_map<std::string, std::string>& attributes) {
  for (const auto& p : attributes) {
    const auto& name = p.first;
    const auto& value = p.second;

    errno = 0;
    if (setxattr(path.data(), name.data(), value.data(), value.size(), 0) ==
        -1) {
      return Status(1, "Failed to set the extended attribute");
    }
  }

  return Status(0);
}
} // namespace osquery

#endif
