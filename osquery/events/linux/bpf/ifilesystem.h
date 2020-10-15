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

class IFilesystem {
 public:
  using Ref = std::unique_ptr<IFilesystem>;
  static Status create(Ref& obj);

  IFilesystem() = default;
  virtual ~IFilesystem() = default;

  virtual bool open(tob::utils::UniqueFd& fd,
                    const std::string& path,
                    int flags) const = 0;

  virtual bool openAt(tob::utils::UniqueFd& fd,
                      int dirfd,
                      const std::string& path,
                      int flags) const = 0;

  virtual bool readLinkAt(std::string& destination,
                          int dirfd,
                          const std::string& path) const = 0;

  virtual bool read(std::vector<char>& buffer,
                    int fd,
                    std::size_t max_size) const = 0;

  using EnumFilesCallback =
      std::function<void(const std::string& name, bool directory)>;

  virtual bool enumFiles(int dirfd, EnumFilesCallback callback) const = 0;

  IFilesystem(const IFilesystem&) = delete;
  IFilesystem& operator=(const IFilesystem&) = delete;
};

} // namespace osquery
