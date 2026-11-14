/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/filesystem/fileops.h>
#include <osquery/filesystem/filesystem.h>

#include <glob.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include <boost/filesystem.hpp>
#include <boost/optional.hpp>

#if defined(__linux__) && !defined(O_PATH)
#define O_PATH 010000000
#endif

namespace fs = boost::filesystem;
namespace errc = boost::system::errc;

namespace osquery {

namespace {

/**
 * @brief Opens the directory name in dir_fd, not through a symlink.
 *
 * On Linux the directory is opened with O_PATH, only to look up names in it,
 * which needs no read permission on it, as a plain open() of a path through it
 * would not. Elsewhere (macOS before 11) it is opened for reading, which needs
 * read permission on it too.
 */
int openDirectoryAt(int dir_fd, const char* name) {
  const int flags = O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
#ifdef __linux__
  return ::openat(dir_fd, name, O_PATH | flags);
#else
  return ::openat(dir_fd, name, O_RDONLY | flags);
#endif
}

/**
 * @brief Opens the regular file at path without following a symlink that was
 * not there when the path was resolved.
 *
 * The path's symlinks are resolved first, and the result must be a regular
 * file before it is opened. On macOS 11 and later it is then opened with
 * O_NOFOLLOW_ANY, which fails if any component of the path is a symlink.
 * Elsewhere each directory of the result is opened from the one before it, and
 * the file from the last one, none of them through a symlink. Either way a path
 * changed after it was resolved makes the open fail, or leads it only to what
 * was put in those directories themselves, never through a symlink to a device
 * elsewhere.
 */
int openResolvedRegularFile(const fs::path& path,
                            int oflag,
                            int perms,
                            struct stat& expected) {
  char* resolved = ::realpath(path.c_str(), nullptr);
  if (resolved == nullptr) {
    return -1;
  }

  std::string real_path(resolved);
  ::free(resolved);

#if defined(__APPLE__) && defined(O_NOFOLLOW_ANY)
  if (__builtin_available(macos 11.0, *)) {
    if (::lstat(real_path.c_str(), &expected) < 0 ||
        !S_ISREG(expected.st_mode)) {
      return -1;
    }
    return ::open(real_path.c_str(), oflag | O_NOFOLLOW_ANY, perms);
  }
#endif

  int dir_fd = openDirectoryAt(AT_FDCWD, "/");
  size_t start = 1;
  size_t end = 0;
  while (dir_fd >= 0 &&
         (end = real_path.find('/', start)) != std::string::npos) {
    auto name = real_path.substr(start, end - start);
    int next_fd = openDirectoryAt(dir_fd, name.c_str());
    ::close(dir_fd);
    dir_fd = next_fd;
    start = end + 1;
  }

  if (dir_fd < 0) {
    return -1;
  }

  auto name = real_path.substr(start);
  int fd = -1;
  if (::fstatat(dir_fd, name.c_str(), &expected, AT_SYMLINK_NOFOLLOW) == 0 &&
      S_ISREG(expected.st_mode)) {
    fd = ::openat(dir_fd, name.c_str(), oflag | O_NOFOLLOW, perms);
  }

  ::close(dir_fd);
  return fd;
}

/**
 * @brief Opens path with oflag, only if it is a regular file.
 *
 * On Linux the type is read through an O_PATH descriptor, which neither blocks
 * nor runs a driver's open, and that same file is then reopened through
 * /proc/self/fd. Without /proc, and on other platforms, the file is opened by
 * openResolvedRegularFile, where O_NONBLOCK and O_NOCTTY keep a FIFO swapped
 * in from blocking the open or a terminal from becoming the controlling one.
 * Either way the opened file must be the regular file that was checked.
 */
int openRegularFile(const fs::path& path, int oflag, int perms) {
  oflag |= O_NONBLOCK | O_NOCTTY | O_CLOEXEC;

  struct stat expected;
  int fd = -1;
#ifdef __linux__
  // Kernels older than O_PATH ignore it and open the file for reading, which
  // O_NONBLOCK and O_NOCTTY keep as harmless.
  int path_fd =
      ::open(path.c_str(), O_PATH | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
  if (path_fd < 0) {
    return -1;
  }

  if (::fstat(path_fd, &expected) < 0 || !S_ISREG(expected.st_mode)) {
    ::close(path_fd);
    return -1;
  }

  auto fd_path = "/proc/self/fd/" + std::to_string(path_fd);
  fd = ::open(fd_path.c_str(), oflag, perms);
  int open_errno = errno;
  ::close(path_fd);

  if (fd < 0 && open_errno != ENOENT) {
    return -1;
  }
#endif

  if (fd < 0) {
    fd = openResolvedRegularFile(path, oflag, perms, expected);
    if (fd < 0) {
      return -1;
    }
  }

  struct stat opened;
  if (::fstat(fd, &opened) < 0 || !S_ISREG(opened.st_mode) ||
      opened.st_dev != expected.st_dev || opened.st_ino != expected.st_ino) {
    ::close(fd);
    return -1;
  }

  return fd;
}

} // namespace

PlatformFile::PlatformFile(const fs::path& path, int mode, int perms)
    : fname_(path) {
  int oflag = 0;
  bool may_create = false;

  if ((mode & PF_READ) == PF_READ && (mode & PF_WRITE) == PF_WRITE) {
    oflag = O_RDWR;
  } else if ((mode & PF_READ) == PF_READ) {
    oflag = O_RDONLY;
  } else if ((mode & PF_WRITE) == PF_WRITE) {
    oflag = O_WRONLY;
  }

  switch (PF_GET_OPTIONS(mode)) {
  case PF_GET_OPTIONS(PF_CREATE_ALWAYS):
    oflag |= O_CREAT | O_TRUNC;
    may_create = true;
    break;
  case PF_GET_OPTIONS(PF_CREATE_NEW):
    oflag |= O_CREAT | O_EXCL;
    may_create = true;
    break;
  case PF_GET_OPTIONS(PF_OPEN_EXISTING):
    // Nothing to do, open will fail with -1 if it doesn't exist
    break;
  case PF_GET_OPTIONS(PF_OPEN_ALWAYS):
    oflag |= O_CREAT;
    may_create = true;
    break;
  case PF_GET_OPTIONS(PF_TRUNCATE):
    if (mode & PF_WRITE) {
      oflag |= O_TRUNC;
    }

    break;
  default:
    break;
  }

  if ((mode & PF_NONBLOCK) == PF_NONBLOCK) {
    oflag |= O_NONBLOCK;
    is_nonblock_ = true;
  }

  if ((mode & PF_APPEND) == PF_APPEND) {
    oflag |= O_APPEND;
  }

  if (perms == -1 && may_create) {
    perms = 0666;
  }

  if ((mode & PF_REGULAR_ONLY) == PF_REGULAR_ONLY) {
    handle_ = openRegularFile(fname_, oflag, perms);
  } else {
    handle_ = ::open(fname_.c_str(), oflag, perms);
  }
}

PlatformFile::~PlatformFile() {
  if (handle_ != kInvalidHandle) {
    ::close(handle_);
    handle_ = kInvalidHandle;
  }
}

bool PlatformFile::isSpecialFile() const {
  return (size() == 0);
}

static uid_t getFileOwner(PlatformHandle handle) {
  struct stat file;
  if (::fstat(handle, &file) < 0) {
    return -1;
  }
  return file.st_uid;
}

Status PlatformFile::isOwnerRoot() const {
  if (!isValid()) {
    return Status(-1, "Invalid handle_");
  }

  uid_t owner_id = getFileOwner(handle_);
  if (owner_id == (uid_t)-1) {
    return Status(-1, "fstat error");
  }

  if (owner_id == 0) {
    return Status::success();
  }
  return Status(1, "Owner is not root");
}

Status PlatformFile::isOwnerCurrentUser() const {
  if (!isValid()) {
    return Status(-1, "Invalid handle_");
  }

  uid_t owner_id = getFileOwner(handle_);
  if (owner_id == (uid_t)-1) {
    return Status(-1, "fstat error");
  }

  if (owner_id == ::getuid()) {
    return Status::success();
  }

  return Status(1, "Owner is not current user");
}

Status PlatformFile::isExecutable() const {
  struct stat file_stat;
  if (::fstat(handle_, &file_stat) < 0) {
    return Status(-1, "fstat error");
  }

  if ((file_stat.st_mode & S_IXUSR) == S_IXUSR) {
    return Status::success();
  }

  return Status(1, "Not executable");
}

Status PlatformFile::hasSafePermissions() const {
  struct stat file;
  if (::fstat(handle_, &file) < 0) {
    return Status(-1, "fstat error");
  }

  // We allow user write for now, since our main threat is external
  // modification by other users
  if ((file.st_mode & S_IWOTH) == 0) {
    return Status::success();
  }

  return Status(1, "Writable");
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
  TIMESPEC_TO_TIMEVAL(&times.times[0], &file.st_atim);
  TIMESPEC_TO_TIMEVAL(&times.times[1], &file.st_mtim);
#else
  TIMESPEC_TO_TIMEVAL(&times.times[0], &file.st_atimespec);
  TIMESPEC_TO_TIMEVAL(&times.times[1], &file.st_mtimespec);
#endif

  return true;
}

bool PlatformFile::setFileTimes(const PlatformTime& times) {
  if (!isValid()) {
    return false;
  }

  return (::futimes(handle_, times.times) == 0);
}

ssize_t PlatformFile::read(void* buf, size_t nbyte) {
  if (!isValid()) {
    return -1;
  }

  has_pending_io_ = false;
  auto ret = ::read(handle_, buf, nbyte);
  if (ret < 0 && errno == EAGAIN) {
    has_pending_io_ = true;
  } else if (ret > 0 && static_cast<size_t>(ret) < nbyte) {
    // This handles a (bug?) in Linux where special files are labeled as normal
    // for example: /sys nodes that must be read in pages.
    has_pending_io_ = true;
  }

  return ret;
}

ssize_t PlatformFile::write(const void* buf, size_t nbyte) {
  if (!isValid()) {
    return -1;
  }

  has_pending_io_ = false;
  auto ret = ::write(handle_, buf, nbyte);
  if (ret < 0 && errno == EAGAIN) {
    has_pending_io_ = true;
  }
  return ret;
}

off_t PlatformFile::seek(off_t offset, SeekMode mode) {
  if (!isValid()) {
    return -1;
  }

  int whence = 0;
  switch (mode) {
  case PF_SEEK_BEGIN:
    whence = SEEK_SET;
    break;
  case PF_SEEK_CURRENT:
    whence = SEEK_CUR;
    break;
  case PF_SEEK_END:
    whence = SEEK_END;
    break;
  default:
    break;
  }
  return ::lseek(handle_, offset, whence);
}

size_t PlatformFile::size() const {
  struct stat file;
  if (::fstat(handle_, &file) < 0) {
    // This is an error case, but the size is not signed.
    return 0;
  }
  return file.st_size;
}

boost::optional<std::string> getHomeDirectory() {
  // Try to get the caller's home directory using HOME and getpwuid.
  auto user = ::getpwuid(getuid());
  auto homedir = getEnvVar("HOME");
  if (homedir.is_initialized()) {
    // Fail over to the users home directory if HOME is not writable.
    if (isWritable(*homedir)) {
      return homedir;
    }
  }

  if (user != nullptr && user->pw_dir != nullptr) {
    return std::string(user->pw_dir);
  } else {
    return boost::none;
  }
}

bool platformSetSafeDbPerms(const std::string& path) {
  return platformChmod(path, S_IRWXU);
}

bool platformChmod(const std::string& path, mode_t perms) {
  return (::chmod(path.c_str(), perms) == 0);
}

Status platformCreatePrivateDir(const fs::path& path) {
  // Create the directory with no group/other permissions to avoid a window
  // where it is accessible by other users.
  if (::mkdir(path.c_str(), S_IRWXU) != 0) {
    return Status::failure("Failed to create private directory: " +
                           path.string());
  }

  // mkdir is affected by umask; ensure the owner retains full rwx. This does
  // not widen access for group/other because those bits are not set.
  if (::chmod(path.c_str(), S_IRWXU) != 0) {
    ::rmdir(path.c_str());
    return Status::failure("Failed to set private directory permissions: " +
                           path.string());
  }

  return Status::success();
}

std::vector<std::string> platformGlob(const std::string& find_path) {
  std::vector<std::string> results;

  auto data = (glob_t*)alloca(sizeof(glob_t));
  ::glob(find_path.c_str(), GLOB_TILDE | GLOB_MARK | GLOB_BRACE, nullptr, data);
  size_t count = data->gl_pathc;

  for (size_t index = 0; index < count; index++) {
    results.push_back(data->gl_pathv[index]);
  }

  ::globfree(data);
  return results;
}

int platformAccess(const std::string& path, mode_t mode) {
  return ::access(path.c_str(), mode);
}

Status platformIsTmpDir(const fs::path& dir) {
  struct stat dir_stat;
  if (::stat(dir.c_str(), &dir_stat) < 0) {
    return Status(-1, "");
  }

  if (dir_stat.st_mode & (1 << 9)) {
    return Status::success();
  }

  return Status(1, "");
}

// Reduce this to be a lstat check for symlink stuff
Status platformIsFileAccessible(const fs::path& path) {
  struct stat link_stat;
  if (::lstat(path.c_str(), &link_stat) < 0) {
    return Status(1, "File is not accessible");
  }
  return Status::success();
}

bool platformIsatty(FILE* f) {
  return 0 != isatty(fileno(f));
}

boost::optional<FILE*> platformFopen(const std::string& filename,
                                     const std::string& mode) {
  auto fp = ::fopen(filename.c_str(), mode.c_str());
  if (fp == nullptr) {
    return boost::none;
  }

  return fp;
}

Status socketExists(const fs::path& path, bool remove_socket) {
  // This implies that the socket is writable.
  if (pathExists(path).ok()) {
    if (!isWritable(path).ok()) {
      return Status(1, "Cannot write extension socket: " + path.string());
    } else if (remove_socket && !removePath(path).ok()) {
      return Status(1, "Cannot remove extension socket: " + path.string());
    }
  } else {
    // The path does not exist.
    if (!pathExists(path.parent_path()).ok()) {
      return Status(1, "Extension socket directory missing: " + path.string());
    } else if (!isWritable(path.parent_path()).ok()) {
      return Status(1, "Cannot create extension socket: " + path.string());
    }

    // If we are not requesting to remove the socket then this is a failure.
    if (!remove_socket) {
      return Status(1, "Socket does not exist");
    }
  }
  return Status(0);
}

fs::path getSystemRoot() {
  return fs::path("/");
}

Status platformLstat(const std::string& path, struct stat& d_stat) {
  if (::lstat(path.c_str(), &d_stat) < 0) {
    return Status(1);
  }
  return Status(0);
}

boost::optional<bool> platformIsFile(int fd) {
  struct stat d_stat {};
  if (::fstat(fd, &d_stat) < 0) {
    return boost::none;
  }

  return S_ISREG(d_stat.st_mode);
}

Status platformFileno(FILE* file, int& fd) {
  fd = ::fileno(file);

  if (fd < 0) {
    return Status(errno);
  }

  return Status::success();
}
} // namespace osquery
