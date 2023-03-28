/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/filesystem/fileops.h>
#include <osquery/filesystem/posix/xattrs.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/scope_guard.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>

namespace osquery {
#if defined(__APPLE__)
#define flistxattr(fd, buffer, buffer_size)                                    \
  ::flistxattr(fd, buffer, buffer_size, 0)

#define fgetxattr(fd, attr_name, buffer, buffer_size)                          \
  ::fgetxattr(fd, attr_name, buffer, buffer_size, 0, 0)
#endif

std::string xAttrFileErrorToString(XAttrFileError error,
                                   const std::string& path) {
  std::string error_message;
  switch (error) {
  case XAttrFileError::List: {
    error_message +=
        "Failed to list the extended attributes for the following path: ";
    error_message += path;
    break;
  }
  case XAttrFileError::NoLength: {
    error_message +=
        "Failed to determine the length the extended attribute "
        "list for the following path: ";
    error_message += path;
    break;
  }
  case XAttrFileError::SizeChanged: {
    error_message +=
        "Failed to list the extended attributes for the following path: ";
    error_message += path;
    error_message +=
        ". The list of extended attributes has changed while it was being "
        "acquired.";
    break;
  }
  }
  return error_message;
}

std::string xAttrValueErrorToString(XAttrValueError error,
                                    const std::string& path,
                                    const std::string& name) {
  std::string error_message;
  switch (error) {
  case XAttrValueError::NoLength: {
    error_message +=
        "Failed to determine the length of the extended attribute named '";
    error_message += name;
    error_message += "' from the following path: ";
    error_message += path;
    break;
  }
  case XAttrValueError::Get: {
    error_message += "Failed to acquire the extended attribute named '";
    error_message += name;
    error_message += "' from the following path: ";
    error_message += path;
    break;
  }
  case XAttrValueError::SizeChanged: {
    error_message += "Failed to acquire the extended attribute named '";
    error_message += name;
    error_message += "' from the following path: ";
    error_message += path;
    error_message +=
        ". The extended attribute value has been changed while it was being "
        "acquired.";
    break;
  }
  }

  return error_message;
}

XAttrNameListResult getExtendedAttributesNames(int fd) {
  std::vector<std::string> name_list;

  auto buffer_size = flistxattr(fd, nullptr, 0);
  if (buffer_size == 0) {
    return name_list;

  } else if (buffer_size < 0) {
    return createError(XAttrFileError::NoLength);
  }

  std::vector<char> buffer(static_cast<std::size_t>(buffer_size), 0);

  auto err = flistxattr(fd, buffer.data(), buffer.size());
  if (err == 0) {
    return name_list;

  } else if (err < 0) {
    return createError(XAttrFileError::List);
  }

  if (err < buffer_size) {
    buffer.resize(static_cast<std::size_t>(err));

  } else if (err > buffer_size) {
    return createError(XAttrFileError::SizeChanged);
  }

  std::size_t start_index{0U};
  for (std::size_t i{0U}; i < buffer.size(); ++i) {
    if (buffer[i] != 0) {
      continue;
    }

    const char* name_ptr = buffer.data() + start_index;
    auto name_length = i - start_index;
    start_index = i + 1U;

    auto name = std::string(name_ptr, name_length);
    name_list.emplace_back(std::move(name));
  }

  return name_list;
}

XAttrValueResult getExtendedAttributeValue(int fd, const std::string& name) {
  auto buffer_size = fgetxattr(fd, name.c_str(), nullptr, 0);
  if (buffer_size == 0) {
    return XAttrValueResult::success({});
  } else if (buffer_size < 0) {
    return createError(XAttrValueError::NoLength);
  }

  ExtendedAttributeValue value(static_cast<std::size_t>(buffer_size), 0U);

  auto err = fgetxattr(fd, name.c_str(), value.data(), value.size());
  if (err == 0) {
    return value;

  } else if (err < 0) {
    return createError(XAttrValueError::Get);
  }

  if (err < buffer_size) {
    value.resize(static_cast<std::size_t>(err));

  } else if (err > buffer_size) {
    return createError(XAttrValueError::SizeChanged);
  }

  return value;
}

XAttrGetResult getExtendedAttributes(const std::string& path) {
  int fd = open(path.c_str(), O_RDONLY);

  if (fd < 0) {
    if (errno == ENOENT) {
      return createError(XAttrGetError::NoFile);
    }

    std::string error_message =
        "Failed to open file to read extended attributes at the "
        "following path: ";
    error_message += path;

    return XAttrGetResult::failure(XAttrGetError::GenericError,
                                   std::move(error_message));
  }

  auto fd_guard = scope_guard::create([&] { close(fd); });

  auto list_result = getExtendedAttributesNames(fd);
  if (list_result.isError()) {
    std::string error_message =
        xAttrFileErrorToString(list_result.getErrorCode(), path);

    return XAttrGetResult::failure(std::move(error_message));
  }

  ExtendedAttributeMap xattr_map;
  auto name_list = list_result.take();

  bool had_value_error = false;
  for (const auto& name : name_list) {
    auto value_result = getExtendedAttributeValue(fd, name);
    if (value_result.isError()) {
      /* NOTE: here we don't return an error to the caller, because we
         potentially would need to collect a lot of error messages.
         We could coalesce the errors in a single generic one only,
         without printing anything here, but then we would lose
         on important information about what exactly has gone wrong. */
      had_value_error = true;
      VLOG(1) << xAttrValueErrorToString(
          value_result.getErrorCode(), path, name);

      continue;
    }
    xattr_map.emplace(name, value_result.take());
  }

  if (had_value_error) {
    LOG(ERROR) << "Failed to read some extended attributes from " << path;
  }

  return xattr_map;
}
} // namespace osquery
