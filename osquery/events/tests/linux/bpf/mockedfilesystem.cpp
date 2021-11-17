/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "mockedfilesystem.h"

#include <string>
#include <unordered_map>

namespace osquery {

namespace {

const std::string kMockedStatFile{
    "33622 (zsh) S 33616 33622 33622 34818 33662 4194304 1679 1186 1 1 2 1 1 0 "
    "20 0 1 0 3767695 10260480 1469 18446744073709551615 94211933335552 "
    "94211933941589 140736923660608 0 0 0 2 3686404 134295555 0 0 0 17 7 0 0 0 "
    "0 0 94211934083888 94211934113128 94211944632320 140736923667185 "
    "140736923667198 140736923667198 140736923668459 0\n"};

const char kCmdLine[] = "zsh\0-i\0-H\0";

} // namespace

bool MockedFilesystem::open(tob::utils::UniqueFd& fd,
                            const std::string& path,
                            int flags) const {
  if (path == "/proc/1001") {
    fd.reset(0xFFFFFF1);

  } else if (path == "/proc/" || path == "/proc") {
    fd.reset(0xFFFFFF2);

  } else if (path == "/proc/1234567") {
    return false;

  } else {
    throw std::logic_error("Invalid path specified in MockedFilesystem::open");
  }

  return true;
}

bool MockedFilesystem::openAt(tob::utils::UniqueFd& fd,
                              int dirfd,
                              const std::string& path,
                              int flags) const {
  if (dirfd == 0xFFFFFF1 && path == "fd") {
    fd.reset(0xFFFFFF3);

  } else if (dirfd == 0xFFFFFF1 && path == "exe") {
    fd.reset(0xFFFFFF6);

  } else if (dirfd == 0xFFFFFF1 && path == "cwd") {
    fd.reset(0xFFFFFF7);

  } else if (dirfd == 0xFFFFFF1 && path == "cmdline") {
    fd.reset(0xFFFFFF8);

  } else if (dirfd == 0xFFFFFF1 && path == "stat") {
    fd.reset(0xFFFFFF9);

  } else if (dirfd == 0xFFFFFF3 && path == "268435444") {
    fd.reset(0xFFFFFF4);

  } else if (dirfd == 0xFFFFFF3 && path == "268435445") {
    fd.reset(0xFFFFFF5);

  } else {
    throw std::logic_error(
        "Invalid dirfd specified in MockedFilesystem::openAt");
  }

  return true;
}

bool MockedFilesystem::readLinkAt(std::string& destination,
                                  int dirfd,
                                  const std::string& path) const {
  if (dirfd == 0xFFFFFF3 && path == "268435444") {
    destination = "/dev/pts/2";

  } else if (dirfd == 0xFFFFFF3 && path == "268435445") {
    destination = "/dev/pts/3";

  } else if (dirfd == 0xFFFFFF1 && path == "exe") {
    destination = "/usr/bin/zsh";

  } else if (dirfd == 0xFFFFFF1 && path == "cwd") {
    destination = "/home/alessandro";

  } else {
    throw std::logic_error(
        "Invalid fd specified in MockedFilesystem::readLink");
  }

  return true;
}

bool MockedFilesystem::read(std::vector<char>& buffer,
                            int fd,
                            std::size_t max_size) const {
  if (fd == 0xFFFFFF9) {
    // stat file
    buffer.resize(kMockedStatFile.size());
    std::memcpy(buffer.data(), kMockedStatFile.c_str(), kMockedStatFile.size());

    return true;

  } else if (fd == 0xFFFFFF8) {
    // cmdline
    buffer.resize(sizeof(kCmdLine));
    std::memcpy(buffer.data(), kCmdLine, sizeof(kCmdLine));

    return true;
  }

  throw std::logic_error("Invalid fd specified in MockedFilesystem::read");
}

bool MockedFilesystem::enumFiles(int dirfd, EnumFilesCallback callback) const {
  callback("test_folder", true);
  callback("test_file", false);

  if (dirfd == 0xFFFFFF2) {
    callback("1001", true);

  } else if (dirfd == 0xFFFFFF3) {
    callback("268435445", false);
    callback("268435444", false);

  } else {
    throw std::logic_error(
        "Invalid dirfd specified in MockedFilesystem::enumFiles");
  }

  return true;
}

bool MockedFilesystem::fileExists(bool& exists,
                                  int dirfd,
                                  const std::string& name) const {
  if (dirfd == 0xFFFFFF2 && (name == "1000" || name == "1001")) {
    exists = true;
  } else {
    exists = false;
  }

  return true;
}

} // namespace osquery
