/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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

  virtual bool readLink(std::string& destination, int fd) const = 0;

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
