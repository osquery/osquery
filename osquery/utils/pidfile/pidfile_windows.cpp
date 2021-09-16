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
                  GENERIC_READ,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                  nullptr,
                  CREATE_ALWAYS,
                  FILE_ATTRIBUTE_NORMAL,
                  nullptr);

  if (file_handle == INVALID_HANDLE_VALUE) {
    file_handle =
        CreateFileW(stringToWstring(path).c_str(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    0,
                    nullptr);
  }

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

  return fromNativeHandle(file_handle);
}

Expected<Pidfile::FileHandle, Pidfile::Error> Pidfile::lockFile(
    FileHandle file_handle) noexcept {
  // Upgrade the restrictions:
  // - Add write access
  // - Enable the delete on close option
  // - Only share the file for read access
  auto new_handle = ReOpenFile(toNativeHandle(file_handle),
                               GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ,
                               FILE_FLAG_DELETE_ON_CLOSE);

  if (new_handle == INVALID_HANDLE_VALUE) {
    return createError(Error::Busy);
  }

  CloseHandle(toNativeHandle(file_handle));
  return fromNativeHandle(new_handle);
}

boost::optional<Pidfile::Error> Pidfile::writeFile(
    FileHandle file_handle) noexcept {
  auto buffer = getCurrentPID();

  auto buffer_size = static_cast<DWORD>(buffer.size());
  auto remaining_bytes = buffer_size;

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

  if (remaining_bytes != 0) {
    return Pidfile::Error::IOError;
  }

  return boost::none;
}

Expected<std::string, Pidfile::Error> Pidfile::readFile(
    FileHandle file_handle) noexcept {
  LARGE_INTEGER file_size{};
  if (!GetFileSizeEx(toNativeHandle(file_handle), &file_size)) {
    return createError(Pidfile::Error::IOError);
  }

  auto buffer_size =
      std::min(static_cast<DWORD>(file_size.QuadPart), static_cast<DWORD>(32));

  std::string buffer(buffer_size, 0);

  auto remaining_bytes = buffer.size();

  for (int retry = 0; retry < 5; ++retry) {
    auto buffer_ptr = buffer.data() + buffer.size() - remaining_bytes;

    DWORD bytes_read{};
    if (!ReadFile(toNativeHandle(file_handle),
                  buffer_ptr,
                  remaining_bytes,
                  &bytes_read,
                  nullptr)) {
      break;
    }

    remaining_bytes -= static_cast<std::size_t>(bytes_read);
  }

  return buffer;
}

void Pidfile::closeFile(FileHandle file_handle) noexcept {
  CloseHandle(toNativeHandle(file_handle));
}

void Pidfile::destroyFile(FileHandle file_handle, const std::string&) noexcept {
  closeFile(file_handle);
}

} // namespace osquery
