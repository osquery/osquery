/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <boost/optional.hpp>

#include <osquery/utils/expected/expected.h>

#include <filesystem>
#include <memory>

namespace osquery {

class Pidfile final {
 public:
  enum class Error {
    Unknown,
    Busy,
    NotRunning,
    AccessDenied,
    MemoryAllocationFailure,
    IOError,
    InvalidProcessID,
  };

  static Expected<Pidfile, Error> create(const std::string& path) noexcept;
  static Expected<std::uint64_t, Error> read(const std::string& path) noexcept;

  ~Pidfile();

  Pidfile(Pidfile&& other) noexcept;
  Pidfile& operator=(Pidfile&& other) noexcept;

  Pidfile(const Pidfile&) = delete;
  Pidfile& operator=(const Pidfile&) = delete;

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  Pidfile(const std::string& path);

 public:
  using FileHandle = std::int64_t;

  static Expected<FileHandle, Error> createFile(
      const std::string& path) noexcept;

  static Expected<FileHandle, Error> lockFile(FileHandle file_handle) noexcept;

  static Expected<std::string, Error> readFile(FileHandle file_handle) noexcept;

  static boost::optional<Error> writeFile(FileHandle file_handle) noexcept;

  static void closeFile(FileHandle file_handle) noexcept;

  static void destroyFile(FileHandle file_handle,
                          const std::string& path) noexcept;
};

std::ostream& operator<<(std::ostream& stream, const Pidfile::Error& error);

} // namespace osquery
