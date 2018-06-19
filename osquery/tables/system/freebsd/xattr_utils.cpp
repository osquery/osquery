/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <string>
#include <vector>

#include <sys/extattr.h>

#include "osquery/tables/system/posix/xattr_utils.h"

namespace osquery {
namespace {
Status getExtendedAttributeListSize(size_t& size,
                                    const std::string& path,
                                    int namespace_) {
  auto length = extattr_list_file(path.data(), namespace_, nullptr, 0);
  if (length == -1) {
    return Status(
        1,
        "Failed to list the extended attributes for the following file: " +
            path);
  }

  size = static_cast<size_t>(length);
  return Status(0);
}

Status getRawExtendedAttributeList(std::string& buffer,
                                   const std::string& path,
                                   int namespace_) {
  size_t list_size;
  auto s = getExtendedAttributeListSize(list_size, path, namespace_);
  if (!s.ok()) {
    return s;
  }

  buffer.resize(list_size);
  if (buffer.size() != list_size) {
    return Status(1, "Memory allocation failure");
  }

  auto read_bytes =
      extattr_list_file(path.data(), namespace_, &buffer[0], buffer.size());
  if (read_bytes == -1) {
    return Status(
        1,
        "Failed to acqiore the extended attributes for the following file: " +
            path);
  }

  return Status(0);
}

Status getExtendedAttributeList(std::vector<std::string>& attribute_list,
                                const std::string& path,
                                int namespace_) {
  attribute_list.clear();

  std::string raw_attribute_list;
  auto s = getRawExtendedAttributeList(raw_attribute_list, path, namespace_);
  if (!s.ok()) {
    return s;
  }

  size_t index = 0U;
  while (index < raw_attribute_list.size()) {
    auto name_length = static_cast<size_t>(raw_attribute_list[index]);
    index++;

    if (index + name_length > raw_attribute_list.size()) {
      return Status(1, "Unexpected attribute list format");
    }

    auto current_attribute_name = raw_attribute_list.substr(index, name_length);
    index += name_length;

    attribute_list.push_back(current_attribute_name);
  }

  return Status(0);
}

Status getExtendedAttribute(std::string& value,
                            const std::string& path,
                            int namespace_,
                            const std::string& name) {
  value.clear();

  auto buffer_size =
      extattr_get_file(path.data(), namespace_, name.data(), nullptr, 0U);
  if (buffer_size == -1) {
    return Status(1, "Failed to retrieve the extended attribute length");
  }

  value.resize(static_cast<size_t>(buffer_size));
  if (value.size() != static_cast<size_t>(buffer_size)) {
    return Status(1, "Memory allocation failure");
  }

  buffer_size = extattr_get_file(
      path.data(), namespace_, name.data(), &value[0], value.size());
  if (buffer_size == -1) {
    return Status(1, "Failed to read the extended attribute");
  }

  if (value.size() != static_cast<size_t>(buffer_size)) {
    value.resize(buffer_size);
  }

  return Status(0);
}

Status appendExtendedAttributesForNamespace(ExtendedAttributes& attributes,
                                            const std::string& path,
                                            int namespace_) {
  std::vector<std::string> attribute_list;
  auto s = getExtendedAttributeList(attribute_list, path, namespace_);
  if (!s.ok()) {
    return s;
  }

  std::string name_prefix =
      (namespace_ == EXTATTR_NAMESPACE_USER) ? "user." : "system.";

  for (const auto& attribute_name : attribute_list) {
    std::string attribute_value;
    s = getExtendedAttribute(attribute_value, path, namespace_, attribute_name);
    if (!s.ok()) {
      return s;
    }

    attributes.push_back(
        std::make_pair(name_prefix + attribute_name, attribute_value));
  }

  return Status(0);
}
} // namespace

Status getExtendedAttributes(ExtendedAttributes& attributes,
                             const std::string& path) {
  attributes.clear();

  for (int namespace_ : {EXTATTR_NAMESPACE_USER, EXTATTR_NAMESPACE_SYSTEM}) {
    auto s = appendExtendedAttributesForNamespace(attributes, path, namespace_);
    if (!s.ok()) {
      return s;
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

    if (extattr_set_file(path.data(),
                         EXTATTR_NAMESPACE_USER,
                         name.data(),
                         value.data(),
                         value.size()) == -1) {
      return Status(1, "Failed to set the extended attribute");
    }
  }

  return Status(0);
}
} // namespace osquery
