/*
*  Copyright (c) 2014-present, Facebook, Inc.
*  All rights reserved.
*
*  This source code is licensed under the BSD-style license found in the
*  LICENSE file in the root directory of this source tree. An additional grant
*  of patent rights can be found in the PATENTS file in the same directory.
*
*/

#include <glob.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/stat.h>

#include "osquery/filesystem/fileops.h"

namespace osquery {

PlatformFile::PlatformFile(const std::string& path, int mode, int perms) {
  int oflag = 0;

  if ((mode & PF_READ) && (mode & PF_WRITE)) {
    oflag = O_RDWR;
  } else if (mode & PF_READ) {
    oflag = O_RDONLY;
  } else if (mode & PF_WRITE) {
    oflag = O_WRONLY;
  }

  switch ((mode & PF_OPTIONS_MASK) >> 2) {
    case PF_CREATE_NEW:
      oflag |= O_CREAT;
      if (mode & PF_WRITE) oflag |= O_APPEND;
      break;
    case PF_CREATE_ALWAYS:
      oflag |= O_CREAT | O_EXCL;
      if (mode & PF_WRITE) oflag |= O_APPEND;
      break;
    case PF_OPEN_ALWAYS:
      oflag |= CREATE_NEW;
      if (mode & PF_WRITE) oflag |= O_APPEND;
      break;
    case PF_TRUNCATE:
      oflag |= O_TRUNC;
      break;
    default:
      break;
  }

  if (mode & PF_NONBLOCK) {
    oflag |= O_NONBLOCK;
    is_nonblock_ = true;
  }

  if (perms == -1) {
    handle_ = ::open(path.c_str(), oflag);
  } else {
    handle_ = ::open(path.c_str(), oflag, perms);
  }
}

PlatformFile::~PlatformFile() { 
  if (handle_ != kInvalidHandle) {
    ::close(handle_);
  }
}

ssize_t PlatformFile::read(void *buf, size_t nbyte) {
  if (!isValid()) return -1;
  return ::read(handle_, buf, nbyte);
}

ssize_t PlatformFile::write(const void *buf, size_t nbyte) {
  if (!isValid()) return -1;
  return ::write(handle_, buf, nbyte);
}

boost::optional<std::string> getHomeDirectory() {
  // Try to get the caller's home directory using HOME and getpwuid.
  auto user = getpwuid(getuid());
  if (getenv("HOME") != nullptr) {
    return std::string(getenv("HOME"));
  }
  else if (user != nullptr && user->pw_dir != nullptr) {
    return std::string(user->pw_dir);
  } else {
    return boost::none;
  }
}

bool platformChmod(const std::string& path, mode_t perms) {
  return (chmod(path.c_str(), perms) == 0);
}

std::vector<std::string> platformGlob(std::string find_path) {
  std::vector<std::string> results;
  
  glob_t data;
  glob(path.c_str(), GLOB_TILDE | GLOB_MARK | GLOB_BRACE, nullptr, &data);
  size_t count = data.gl_pathc;
  
  for (size_t index = 0; index < count; index++) {
    results.push_back(data.gl_pathv[index]);
  }

  globfree(&data);
  return results;
}

int platformAccess(const std::string& path, int mode) {
  return access(path.c_str(), mode);
}
}
