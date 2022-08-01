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
#include <sys/stat.h>
#include <unistd.h>

#include <iostream>

namespace osquery {

namespace {

const int kLockFileMode{0600};

std::string getCurrentPID() noexcept {
  std::stringstream stream;
  stream << std::to_string(getpid());

  return stream.str();
}

} // namespace

//
// Make sure that the pidfile can't be opened by unprivileged
// users, otherwise they can lock the file before us
//
// See https://man7.org/linux/man-pages/man2/flock.2.html#DESCRIPTION
//
// >> A shared or exclusive lock can be placed on a file regardless of
// >> the mode in which the file was opened.
//
// Always create the file with the 0600 mode. The ::lockFile() method
// will also force this mode with fchmod()

Expected<Pidfile::FileHandle, Pidfile::Error> Pidfile::createFile(
    const std::string& path) noexcept {
  FileHandle file_handle{};

  for (int retry = 0; retry < 5; ++retry) {
    file_handle =
        open(path.c_str(), O_CREAT | O_RDWR | O_APPEND, kLockFileMode);
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

  return file_handle;
}

Expected<Pidfile::FileHandle, Pidfile::Error> Pidfile::lockFile(
    FileHandle file_handle) noexcept {
  int lock_status{};

  for (int retry = 0; retry < 5; ++retry) {
    lock_status = flock(file_handle, LOCK_NB | LOCK_EX);
    if (lock_status == -1 && errno == EINTR) {
      continue;
    }

    break;
  }

  if (lock_status != 0) {
    Error error{Pidfile::Error::Unknown};
    if (errno == EWOULDBLOCK) {
      error = Pidfile::Error::Busy;
    } else if (errno == ENOLCK) {
      error = Pidfile::Error::MemoryAllocationFailure;
    }

    return createError(error);
  }

  if (fchmod(file_handle, kLockFileMode) != 0) {
    return createError(Pidfile::Error::IOError);
  }

  if (fchown(file_handle, getuid(), getgid()) != 0) {
    return createError(Pidfile::Error::IOError);
  }

  return file_handle;
}

boost::optional<Pidfile::Error> Pidfile::writeFile(
    FileHandle file_handle) noexcept {
  auto buffer = getCurrentPID();

  if (ftruncate(file_handle, 0) != 0) {
    return Pidfile::Error::IOError;
  }

  auto buffer_size = static_cast<ssize_t>(buffer.size());
  auto remaining_bytes = buffer_size;

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

  if (remaining_bytes != 0) {
    return Pidfile::Error::IOError;
  }

  return boost::none;
}

Expected<std::string, Pidfile::Error> Pidfile::readFile(
    FileHandle file_handle) noexcept {
  struct stat file_stats {};
  if (fstat(file_handle, &file_stats) != 0) {
    return createError(Pidfile::Error::IOError);
  }

  auto buffer_size = std::min(static_cast<std::size_t>(file_stats.st_size),
                              static_cast<std::size_t>(32U));

  std::string buffer(buffer_size, 0);

  auto remaining_bytes = buffer.size();

  for (int retry = 0; retry < 5 && remaining_bytes > 0; ++retry) {
    auto buffer_ptr = buffer.data() + buffer.size() - remaining_bytes;

    auto bytes_read = ::read(file_handle, buffer_ptr, remaining_bytes);
    if (bytes_read == -1) {
      if (errno == EINTR) {
        continue;
      }

      break;
    }

    remaining_bytes -= bytes_read;
  }

  if (remaining_bytes != 0) {
    return createError(Pidfile::Error::IOError);
  }

  return buffer;
}

void Pidfile::closeFile(FileHandle file_handle) noexcept {
  close(file_handle);
}

void Pidfile::destroyFile(FileHandle file_handle,
                          const std::string& path) noexcept {
  unlink(path.c_str());

  flock(file_handle, LOCK_UN);
  closeFile(file_handle);
}

} // namespace osquery
