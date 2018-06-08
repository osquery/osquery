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
ssize_t getExtendedAttributeListSize(const std::string& path,
                                     bool user_namespace) {
  int namespace_ =
      user_namespace ? EXTATTR_NAMESPACE_USER : EXTATTR_NAMESPACE_SYSTEM;

  auto length = extattr_list_file(path.data(), namespace_, nullptr, 0);
  if (length == -1) {
    return -1;
  }

  return length;
}

bool getRawExtendedAttributeList(std::string& buffer,
                                 const std::string& path,
                                 bool user_namespace) {
  auto list_size = getExtendedAttributeListSize(path, user_namespace);
  if (list_size == -1) {
    return false;
  }

  buffer.resize(static_cast<size_t>(list_size));
  if (buffer.size() != static_cast<size_t>(list_size)) {
    return false;
  }

  int namespace_ =
      user_namespace ? EXTATTR_NAMESPACE_USER : EXTATTR_NAMESPACE_SYSTEM;
  auto read_bytes =
      extattr_list_file(path.data(), namespace_, &buffer[0], buffer.size());
  if (read_bytes == -1) {
    return false;
  }

  return true;
}

bool getExtendedAttributeList(std::vector<std::string>& attribute_list,
                              const std::string& path,
                              bool user_namespace) {
  attribute_list.clear();

  std::string raw_attribute_list;
  if (!getRawExtendedAttributeList(raw_attribute_list, path, user_namespace)) {
    return false;
  }

  size_t index = 0U;
  while (index < raw_attribute_list.size()) {
    auto name_length = static_cast<size_t>(raw_attribute_list[index]);
    index++;

    if (index + name_length > raw_attribute_list.size()) {
      return false;
    }

    auto current_attribute_name = raw_attribute_list.substr(index, name_length);
    index += name_length;

    attribute_list.push_back(current_attribute_name);
  }

  return true;
}

bool getExtendedAttribute(std::string& value,
                          const std::string& path,
                          bool user_namespace,
                          const std::string& name) {
  value.clear();

  int namespace_ =
      user_namespace ? EXTATTR_NAMESPACE_USER : EXTATTR_NAMESPACE_SYSTEM;

  auto buffer_size =
      extattr_get_file(path.data(), namespace_, name.data(), nullptr, 0U);
  if (buffer_size == -1) {
    return false;
  }

  value.resize(static_cast<size_t>(buffer_size));
  if (value.size() != static_cast<size_t>(buffer_size)) {
    return false;
  }

  buffer_size = extattr_get_file(
      path.data(), namespace_, name.data(), &value[0], value.size());
  if (buffer_size == -1) {
    return false;
  }

  if (value.size() != static_cast<size_t>(buffer_size)) {
    value.resize(buffer_size);
  }

  return true;
}

bool appendExtendedAttributesForNamespace(ExtendedAttributes& attributes,
                                          const std::string& path,
                                          bool user_namespace) {
  std::vector<std::string> attribute_list;
  if (!getExtendedAttributeList(attribute_list, path, user_namespace)) {
    return false;
  }

  std::string name_prefix = user_namespace ? "user." : "system.";

  for (const auto& attribute_name : attribute_list) {
    std::string attribute_value;
    if (!getExtendedAttribute(
            attribute_value, path, user_namespace, attribute_name)) {
      return false;
    }

    attributes.push_back(
        std::make_pair(name_prefix + attribute_name, attribute_value));
  }

  return true;
}
} // namespace

bool getExtendedAttributes(ExtendedAttributes& attributes,
                           const std::string& path) {
  attributes.clear();

  if (!appendExtendedAttributesForNamespace(attributes, path, true)) {
    return false;
  }

  if (!appendExtendedAttributesForNamespace(attributes, path, false)) {
    return false;
  }

  return true;
}

// Used by the tests in
// osquery/tables/system/posix/tests/extended_attributes_tests.cpp
bool setExtendedAttributes(
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
      return false;
    }
  }

  return true;
}
} // namespace osquery
