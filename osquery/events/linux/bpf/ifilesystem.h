/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <memory>
#include <string>
#include <vector>

#include <tob/utils/uniquefd.h>

#include <osquery/utils/status/status.h>

namespace osquery {

/// \brief Filesystem utilities based on fd accesses
/// The main goal of this class is to provide an interface that can be
/// easily mocked up for tests, while also implementing utilities to
/// access files and folders using paths relative to directory file
/// descriptors to reduce race conditions in path transversals (useful
/// for procfs)
class IFilesystem {
 public:
  using Ref = std::unique_ptr<IFilesystem>;
  static Status create(Ref& obj);

  IFilesystem() = default;
  virtual ~IFilesystem() = default;

  /// \brief Wrapper around open()
  virtual bool open(tob::utils::UniqueFd& fd,
                    const std::string& path,
                    int flags) const = 0;

  /// \brief Wrapper around openat()
  virtual bool openAt(tob::utils::UniqueFd& fd,
                      int dirfd,
                      const std::string& path,
                      int flags) const = 0;

  /// \brief Wrapper around readlinkat()
  virtual bool readLinkAt(std::string& destination,
                          int dirfd,
                          const std::string& path) const = 0;

  /// \brief Wrapper around read()
  virtual bool read(std::vector<char>& buffer,
                    int fd,
                    std::size_t max_size) const = 0;

  using EnumFilesCallback =
      std::function<void(const std::string& name, bool directory)>;

  /// \brief Enumerates all the files in the given directory
  virtual bool enumFiles(int dirfd, EnumFilesCallback callback) const = 0;

  /// \brief Checks whether the given file exists or not
  virtual bool fileExists(bool& exists,
                          int dirfd,
                          const std::string& name) const = 0;

  IFilesystem(const IFilesystem&) = delete;
  IFilesystem& operator=(const IFilesystem&) = delete;
};

} // namespace osquery
