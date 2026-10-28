/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/events/linux/bpf/ifilesystem.h>

namespace osquery {

class MockedFilesystem final : public IFilesystem {
 public:
  MockedFilesystem() = default;
  virtual ~MockedFilesystem() override = default;

  virtual bool open(tob::utils::UniqueFd& fd,
                    const std::string& path,
                    int flags) const override;

  virtual bool openAt(tob::utils::UniqueFd& fd,
                      int dirfd,
                      const std::string& path,
                      int flags) const override;

  virtual bool readLinkAt(std::string& destination,
                          int dirfd,
                          const std::string& path) const override;

  virtual bool read(std::vector<char>& buffer,
                    int fd,
                    std::size_t max_size) const override;

  virtual bool enumFiles(int dirfd, EnumFilesCallback callback) const override;

  virtual bool fileExists(bool& exists,
                          int dirfd,
                          const std::string& name) const override;
};

} // namespace osquery
