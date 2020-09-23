/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/events/linux/bpf/ifilesystem.h>

namespace osquery {
class Filesystem final : public IFilesystem {
 public:
  virtual ~Filesystem() override = default;

  virtual bool open(tob::utils::UniqueFd& fd,
                    const std::string& path,
                    int flags) const override;

  virtual bool openAt(tob::utils::UniqueFd& fd,
                      int dirfd,
                      const std::string& path,
                      int flags) const override;

  virtual bool readLink(std::string& destination, int fd) const override;

  virtual bool read(std::vector<char>& buffer,
                    int fd,
                    std::size_t max_size) const override;

  virtual bool enumFiles(int dirfd, EnumFilesCallback callback) const override;

 private:
  Filesystem() = default;

  friend class IFilesystem;
};
} // namespace osquery