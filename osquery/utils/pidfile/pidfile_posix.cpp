/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "pidfile.h"

#include <sys/file.h>
#include <unistd.h>

namespace osquery {

namespace {

bool writeFile(Pidfile::FileHandle file_handle,
               const std::string& buffer) noexcept {
  if (ftruncate(file_handle, 0) != 0) {
    return false;
  }

  ssize_t buffer_size{};
  ssize_t remaining_bytes{};

  buffer_size = remaining_bytes = {static_cast<ssize_t>(buffer.size())};

  for (int retry = 0; retry < 5 && remaining_bytes > 0; ++retry) {
    auto buffer_ptr = buffer.data() + buffer_size - remaining_bytes;

    auto count = write(file_handle, buffer_ptr, remaining_bytes);
    if (count == -1) {
      if (errno == EINTR) {
        continue;
      }

      break;
    }

    remaining_bytes -= count;
  }

  return (remaining_bytes == 0);
}

std::string getCurrentPID() noexcept {
  std::stringstream stream;
  stream << std::to_string(getpid());

  return stream.str();
}

} // namespace

Expected<Pidfile::FileHandle, Pidfile::Error> Pidfile::createFile(
    const std::string& path) noexcept {
  FileHandle file_handle{};

  //
  // Make sure that the pidfile can't be opened by unprivileged
  // users, otherwise they can lock the file before us
  //
  // See https://man7.org/linux/man-pages/man2/flock.2.html#DESCRIPTION
  //
  // >> A shared or exclusive lock can be placed on a file regardless of
  // >> the mode in which the file was opened.
  //

  for (int retry = 0; retry < 5; ++retry) {
    file_handle = open(path.c_str(), O_CREAT | O_WRONLY | O_APPEND, 0400);
    if (file_handle == -1 && errno == EINTR) {
      continue;
    }

    break;
  }

  if (file_handle == -1) {
    Error error{Pidfile::Error::Unknown};
    if (errno == EACCES) {
      error = Pidfile::Error::AccessDenied;
    }

    return createError(error);
  }

  int lock_status{};

  for (int retry = 0; retry < 5; ++retry) {
    lock_status = flock(file_handle, LOCK_NB | LOCK_EX);
    if (lock_status == -1 && errno == EINTR) {
      continue;
    }

    break;
  }

  if (lock_status != 0) {
    close(file_handle);

    Error error{Pidfile::Error::Unknown};
    if (errno == EWOULDBLOCK) {
      error = Pidfile::Error::Busy;
    } else if (errno == ENOLCK) {
      error = Pidfile::Error::MemoryAllocationFailure;
    }

    return createError(error);
  }

  if (!writeFile(file_handle, getCurrentPID())) {
    close(file_handle);
    return createError(Pidfile::Error::IOError);
  }

  return file_handle;
}

void Pidfile::closeFile(FileHandle file_handle,
                        const std::string& path) noexcept {
  unlink(path.c_str());

  flock(file_handle, LOCK_UN);
  close(file_handle);
}

} // namespace osquery
