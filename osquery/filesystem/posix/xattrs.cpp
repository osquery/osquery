/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/filesystem/posix/xattrs.h>
#include <osquery/logger/logger.h>

#include <sys/xattr.h>

namespace osquery {
#if defined(__APPLE__)
#define listxattr(path, buffer, buffer_size)                                   \
  ::listxattr(path, buffer, buffer_size, 0)

#define getxattr(path, attr_name, buffer, buffer_size)                         \
  ::getxattr(path, attr_name, buffer, buffer_size, 0, 0)
#endif

Status getExtendedAttributeNameList(std::vector<std::string>& name_list,
                                    const std::string& path) {
  name_list = {};

  auto buffer_size = listxattr(path.c_str(), nullptr, 0);
  if (buffer_size == 0) {
    return Status::success();

  } else if (buffer_size < 0) {
    return Status::failure(
        "Failed to determine the length the extended attribute list for the "
        "following path: " +
        path);
  }

  std::vector<char> buffer(static_cast<std::size_t>(buffer_size), 0);

  auto err = listxattr(path.c_str(), buffer.data(), buffer.size());
  if (err == 0) {
    return Status::success();

  } else if (err < 0) {
    return Status::failure(
        "Failed to list the extended attributes for the following path: " +
        path);
  }

  if (err < buffer_size) {
    buffer.resize(static_cast<std::size_t>(err));

  } else if (err > buffer_size) {
    return Status::failure(
        "Failed to list the extended attributes for the following path: " +
        path +
        ". The list of extended attributes has changed while it was being "
        "acquired.");
  }

  std::size_t start_index{0U};
  for (std::size_t i{0U}; i < buffer.size(); ++i) {
    if (buffer.at(i) != 0) {
      continue;
    }

    const char* name_ptr = buffer.data() + start_index;
    auto name_length = i - start_index;
    start_index = i + 1U;

    auto name = std::string(name_ptr, name_length);
    name_list.push_back(std::move(name));
  }

  return Status::success();
}

Status getExtendedAttributeValue(ExtendedAttributeValue& value,
                                 const std::string& path,
                                 const std::string& name) {
  value = {};

  auto buffer_size = getxattr(path.c_str(), name.c_str(), nullptr, 0);
  if (buffer_size == 0) {
    return Status::success();

  } else if (buffer_size < 0) {
    return Status::failure(
        "Failed to determine the length of the extended attribute named '" +
        name + "' from the following path: " + path);
  }

  ExtendedAttributeValue buffer(static_cast<std::size_t>(buffer_size), 0U);

  auto err = getxattr(path.c_str(), name.c_str(), buffer.data(), buffer.size());
  if (err == 0) {
    return Status::success();

  } else if (err < 0) {
    return Status::failure("Failed to acquire the extended attribute named '" +
                           name + "' from the following path: " + path);
  }

  if (err < buffer_size) {
    buffer.resize(static_cast<std::size_t>(err));

  } else if (err > buffer_size) {
    return Status::failure("Failed to acquire the extended attribute named '" +
                           name + "' from the following path: " + path +
                           ". The extended attribute value has been changed "
                           "while it was being acquired.");
  }

  value = std::move(buffer);
  return Status::success();
}

Status getExtendedAttributes(ExtendedAttributeMap& xattr_map,
                             const std::string& path) {
  xattr_map = {};

  std::vector<std::string> name_list;
  auto status = getExtendedAttributeNameList(name_list, path);
  if (!status.ok()) {
    return status;
  }

  for (const auto& name : name_list) {
    ExtendedAttributeValue value;
    status = getExtendedAttributeValue(value, path, name);
    if (!status.ok()) {
      LOG(ERROR) << status.getMessage();
      continue;
    }

    xattr_map.insert({name, std::move(value)});
  }

  return Status::success();
}
} // namespace osquery
