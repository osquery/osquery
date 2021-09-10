/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "pidfile.h"

#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>

#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {

namespace {

static_assert(sizeof(Pidfile::FileHandle) >= sizeof(HANDLE),
              "Invalid FileHandle size");

HANDLE toNativeHandle(Pidfile::FileHandle file_handle) {
  HANDLE output{};
  std::memcpy(&output, &file_handle, sizeof(output));

  return output;
}

Pidfile::FileHandle fromNativeHandle(HANDLE handle) {
  Pidfile::FileHandle output{};
  std::memcpy(&output, &handle, sizeof(output));

  return output;
}

bool writeFile(Pidfile::FileHandle file_handle,
               const std::string& buffer) noexcept {
  DWORD buffer_size{};
  DWORD remaining_bytes{};

  buffer_size = remaining_bytes = {static_cast<DWORD>(buffer.size())};

  auto native_handle = toNativeHandle(file_handle);

  for (int retry = 0; retry < 5 && remaining_bytes > 0; ++retry) {
    auto buffer_ptr = buffer.data() + buffer_size - remaining_bytes;

    DWORD count{};
    if (WriteFile(
            native_handle, buffer_ptr, remaining_bytes, &count, nullptr) == 0) {
      break;
    }

    remaining_bytes -= count;
  }

  return (remaining_bytes == 0);
}

std::string getCurrentPID() noexcept {
  std::stringstream stream;
  stream << std::to_string(GetCurrentProcessId());

  return stream.str();
}

} // namespace

Expected<Pidfile::FileHandle, Pidfile::Error> Pidfile::createFile(
    const std::string& path) noexcept {
  auto file_handle =
      CreateFileW(stringToWstring(path).c_str(),
                  GENERIC_READ | GENERIC_WRITE,
                  FILE_SHARE_READ,
                  nullptr,
                  CREATE_ALWAYS,
                  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE,
                  nullptr);

  if (file_handle == INVALID_HANDLE_VALUE) {
    Error error{Pidfile::Error::Unknown};

    auto win32_error{GetLastError()};
    if (win32_error == ERROR_SHARING_VIOLATION) {
      error = Pidfile::Error::Busy;
    } else if (win32_error == ERROR_ACCESS_DENIED) {
      error = Pidfile::Error::AccessDenied;
    }

    return createError(error);
  }

  if (!writeFile(fromNativeHandle(file_handle), getCurrentPID())) {
    closeFile(fromNativeHandle(file_handle), path);
    return createError(Pidfile::Error::IOError);
  }

  return fromNativeHandle(file_handle);
}

void Pidfile::closeFile(FileHandle file_handle, const std::string&) noexcept {
  CloseHandle(toNativeHandle(file_handle));
}

} // namespace osquery
