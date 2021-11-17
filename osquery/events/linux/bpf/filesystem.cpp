/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/events/linux/bpf/filesystem.h>
#include <osquery/events/linux/bpf/uniquedir.h>

#include <fcntl.h>
#include <sys/stat.h>

namespace osquery {

bool Filesystem::open(tob::utils::UniqueFd& fd,
                      const std::string& path,
                      int flags) const {
  fd.reset(-1);

  {
    auto handle = ::open(path.c_str(), flags);
    if (handle == -1) {
      return false;
    }

    fd.reset(handle);
  }

  return true;
}

bool Filesystem::openAt(tob::utils::UniqueFd& fd,
                        int dirfd,
                        const std::string& path,
                        int flags) const {
  fd.reset(-1);

  {
    auto handle = openat(dirfd, path.c_str(), flags);
    if (handle == -1) {
      return false;
    }

    fd.reset(handle);
  }

  return true;
}

bool Filesystem::readLinkAt(std::string& destination,
                            int dirfd,
                            const std::string& path) const {
  std::vector<char> buffer(4096);

  auto bytes_read =
      readlinkat(dirfd, path.c_str(), buffer.data(), buffer.size() - 1U);

  if (bytes_read == -1) {
    return false;
  }

  destination.assign(buffer.data(), static_cast<std::size_t>(bytes_read));
  return true;
}

bool Filesystem::read(std::vector<char>& buffer,
                      int fd,
                      std::size_t max_size) const {
  buffer = {};

  std::vector<char> read_buffer(4096);
  while (buffer.size() < max_size) {
    auto err = ::read(fd, read_buffer.data(), read_buffer.size());
    if (err == 0) {
      break;

    } else if (err == -1) {
      return false;
    }

    auto destination_offset = buffer.size();

    auto bytes_read = static_cast<std::size_t>(err);
    buffer.resize(buffer.size() + bytes_read);

    std::memcpy(
        buffer.data() + destination_offset, read_buffer.data(), bytes_read);
  }

  if (buffer.empty()) {
    return false;
  }

  return true;
}

bool Filesystem::enumFiles(int dirfd, EnumFilesCallback callback) const {
  UniqueDir directory(nullptr, closedir);

  {
    auto dir_obj = fdopendir(dirfd);
    if (dir_obj == nullptr) {
      return false;
    }

    directory.reset(dir_obj);
  }

  for (;;) {
    errno = 0;
    auto entry = readdir(directory.get());
    if (entry == nullptr) {
      if (errno == 0 || errno == ENOENT) {
        break;
      }

      return false;
    }

    const char* string_fd = entry->d_name;
    if (std::strcmp(string_fd, "..") == 0 || std::strcmp(string_fd, ".") == 0) {
      continue;
    }

    bool directory;
    if (entry->d_type == DT_DIR) {
      directory = true;
    } else if (entry->d_type == DT_LNK || entry->d_type == DT_REG) {
      directory = false;
    } else {
      continue;
    }

    callback(string_fd, directory);
  }

  return true;
}

bool Filesystem::fileExists(bool& exists,
                            int dirfd,
                            const std::string& name) const {
  struct stat file_stats {};
  if (fstatat(dirfd, name.c_str(), &file_stats, 0) == 0) {
    exists = true;
    return true;

  } else if (errno == ENOENT) {
    exists = false;
    return true;

  } else {
    return false;
  }
}

Status IFilesystem::create(Ref& obj) {
  try {
    obj.reset(new Filesystem());
    return Status::success();

  } catch (const std::bad_alloc&) {
    return Status::failure("Memory allocation failure");

  } catch (const Status& s) {
    return s;
  }
}

} // namespace osquery
