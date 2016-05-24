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
#include <sys/time.h>

#include <boost/filesystem.hpp>
#include <boost/optional.hpp>

#include "osquery/core/process.h"
#include "osquery/filesystem/fileops.h"

namespace fs = boost::filesystem;

namespace osquery {

PlatformFile::PlatformFile(const std::string& path, int mode, int perms) {
  int oflag = 0;
  bool may_create = false;
  bool check_existence = false;

  if ((mode & PF_READ) == PF_READ && (mode & PF_WRITE) == PF_WRITE) {
    oflag = O_RDWR;
  } else if ((mode & PF_READ) == PF_READ) {
    oflag = O_RDONLY;
  } else if ((mode & PF_WRITE) == PF_WRITE) {
    oflag = O_WRONLY;
  }

  switch (PF_GET_OPTIONS(mode)) {
    case PF_GET_OPTIONS(PF_CREATE_ALWAYS):
      oflag |= O_CREAT;
      if (mode & PF_WRITE) oflag |= O_APPEND;
      may_create = true;
      break;
    case PF_GET_OPTIONS(PF_CREATE_NEW):
      oflag |= O_CREAT | O_EXCL;
      if (mode & PF_WRITE) oflag |= O_APPEND;
      may_create = true;
      break;
    case PF_GET_OPTIONS(PF_OPEN_EXISTING):
      if (mode & PF_WRITE) oflag |= O_APPEND;
      check_existence = true;
      break;
    case PF_GET_OPTIONS(PF_TRUNCATE):
      if (mode & PF_WRITE) oflag |= O_TRUNC;
      break;
    default:
      break;
  }

  if ((mode & PF_NONBLOCK) == PF_NONBLOCK) {
    oflag |= O_NONBLOCK;
    is_nonblock_ = true;
  }

  if (perms == -1 && may_create) {
    perms = 0666;
  }

  if (check_existence && !fs::exists(path.c_str())) {
    handle_ = kInvalidHandle;
  } else {
    handle_ = ::open(path.c_str(), oflag, perms);
  }

  cursor_ = 0;
}

PlatformFile::~PlatformFile() { 
  if (handle_ != kInvalidHandle) {
    ::close(handle_);
  }
}

bool PlatformFile::isFile() const {
  struct stat file;
  if (::fstat(handle_, &file) < 0) {
    return false;
  }
  return (file.st_size > 0);
}

bool PlatformFile::getFileTimes(PlatformTime& times) {
  if (!isValid()) {
    return false;
  }

  struct stat file;
  if (::fstat(handle_, &file) < 0) {
    return false;
  }

#if defined(__linux__)
  TIMESPEC_TO_TIMEVAL(&times[0], &file.st_atim);
  TIMESPEC_TO_TIMEVAL(&times[1], &file.st_mtim);
#else
  TIMESPEC_TO_TIMEVAL(&times[0], &file.st_atimespec);
  TIMESPEC_TO_TIMEVAL(&times[1], &file.st_mtimespec);
#endif

  return true;
}

bool PlatformFile::setFileTimes(const PlatformTime& times) {
  if (!isValid()) {
    return false;
  }

  return (::futimes(handle_, times) == 0);
}

ssize_t PlatformFile::read(void *buf, size_t nbyte) {
  if (!isValid()) {
    return -1;
  }
  return ::read(handle_, buf, nbyte);
}

ssize_t PlatformFile::write(const void *buf, size_t nbyte) {
  if (!isValid()) {
    return -1;
  }
  return ::write(handle_, buf, nbyte);
}

off_t PlatformFile::seek(off_t offset, SeekMode mode) {
  if (!isValid()) {
    return -1;
  }

  int whence = 0;
  switch (mode) {
    case PF_SEEK_BEGIN: whence = SEEK_SET; break;
    case PF_SEEK_CURRENT: whence = SEEK_CUR; break;
    case PF_SEEK_END: whence = SEEK_END; break;
    default: break;
  }
  return ::lseek(handle_, offset, whence);
}

boost::optional<std::string> getHomeDirectory() {
  // Try to get the caller's home directory using HOME and getpwuid.
  auto user = getpwuid(getuid());
  auto homeVar = getEnvVar("HOME");
  if (homeVar.is_initialized()) {
    return *homeVar;
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

std::vector<std::string> platformGlob(const std::string& find_path) {
  std::vector<std::string> results;
  
  glob_t data;
  glob(find_path.c_str(), GLOB_TILDE | GLOB_MARK | GLOB_BRACE, nullptr, &data);
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

