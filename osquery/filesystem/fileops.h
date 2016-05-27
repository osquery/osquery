/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <fcntl.h>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <sys/types.h>

#ifdef WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#endif

#include <boost/optional.hpp>

namespace osquery {

#ifdef WIN32

using mode_t = int;
using ssize_t = SSIZE_T;
using PlatformHandle = HANDLE;
using PlatformTimeType = FILETIME;

// Windows does not define these, X_OK on Windows just ensures that the
// file is readable.
#define F_OK 0
#define R_OK 4
#define W_OK 2
#define X_OK R_OK

#else

using PlatformHandle = int;
using PlatformTimeType = struct timeval;
#endif

using PlatformTime = struct {
  PlatformTimeType times[2];
};

// Constant for an invalid handle
const PlatformHandle kInvalidHandle = (PlatformHandle)-1;

/**
 * @brief File access modes for PlatformFile
 *
 * A file can be opened for many access modes with a variety of different
 * options on Windows and POSIX. To provide multi-platform support, we need to
 * provide an abstraction that can cover the supported platforms.
 */

#define PF_READ 0x0001
#define PF_WRITE 0x0002

#define PF_OPTIONS_MASK 0x001c
#define PF_GET_OPTIONS(x) ((x & PF_OPTIONS_MASK) >> 2)
#define PF_CREATE_NEW (0 << 2)
#define PF_CREATE_ALWAYS (1 << 2)
#define PF_OPEN_EXISTING (2 << 2)
#define PF_TRUNCATE (3 << 2)

#define PF_NONBLOCK 0x0020

/**
 * @brief Modes for seeking through a file
 *
 * Provides a platform agnostic enumeration for file seek operations. These
 * are translated to the appropriate flags for the underlying platform.
 */

enum SeekMode {
  PF_SEEK_BEGIN = 0,
  PF_SEEK_CURRENT,
  PF_SEEK_END
};

#ifdef WIN32

/**
 * @brief Stores information about the last Windows async request
 *
 * Windows-only class that deals with simulating POSIX asynchronous IO semantics
 * using Windows API calls
 */
struct AsyncEvent {
 AsyncEvent();
 ~AsyncEvent();
 
 OVERLAPPED overlapped_{ 0 };
 std::unique_ptr<char[]> buffer_{ nullptr };
 bool is_active_{ false };
};

#endif

/**
 * @brief Platform-agnostic file object
 *
 * PlatformFile is a multi-platform class that offers input/output capabilities for files. 
 */
class PlatformFile {
 public:
  explicit PlatformFile(const std::string& path, int mode, int perms = -1);
  explicit PlatformFile(PlatformHandle handle) : handle_(handle) {}

  PlatformFile(PlatformFile&& src) {
    handle_ = kInvalidHandle;
    std::swap(handle_, src.handle_);
  }

  ~PlatformFile();

  // Checks to see if the file object is actually a disk file and not a "special file"
  bool isFile() const;

  /**
   * @brief Checks to see if there are any pending IO operations.
   *
   * This is mostly used after a read()/write() error in non-blocking mode to
   * determine the intention of the error. If read()/write() returns an error
   * and hasPendingIo() is true, this indicates that the read()/write()
   * operation didn't complete on time.
   */
  bool hasPendingIo() const { return has_pending_io_;  }

  // Checks to see if the handle backing the PlatformFile object is valid
  bool isValid() const { return (handle_ != kInvalidHandle); }

  // Returns the platform specific handle
  PlatformHandle nativeHandle() const { return handle_; }

  /**
   * @brief Returns true if the file's owner is root
   * @note This will always return false on Windows at the moment. In POSIX,
   *       if the fstat call within isOwnerRoot fails, this function will also
   *       return false.
   */
  bool isOwnerRoot() const;

  bool getFileTimes(PlatformTime& times);
  bool setFileTimes(const PlatformTime& times);


  /**
   * @note Currently, we have rudimentary support for non-blocking operations
   *       on Windows. The implementation attempts to emulate POSIX non-blocking
   *       IO semantics using the Windows asynchronous API. As such, there are
   *       currently limitations. For example, opening a non-blocking file with 
   *       read and write privileges may produce some problems. If a write 
   *       operation does not immediately succeed, we cancel IO instead of 
   *       waiting on it. As a result, on-going async read operations will get 
   *       cancelled and data might get lost.
   */

  ssize_t read(void *buf, size_t nbyte);
  ssize_t write(const void *buf, size_t nbyte);
  off_t seek(off_t offset, SeekMode mode);

  size_t size() const;

 private:
  PlatformHandle handle_{ kInvalidHandle };

  bool is_nonblock_{ false };
  bool has_pending_io_{ false };
  int cursor_{ 0 };

#ifdef WIN32
  AsyncEvent last_read_;

  ssize_t getOverlappedResultForRead(void *buf, size_t requested_size);
#endif
};

/**
 * @brief Returns the current user's home directory
 *
 * This uses multiple methods to find the current user's home directory. It
 * attempts to use environment variables first and on failure, tries to obtain
 * the path using platform specific functions. Returns a boost::none on the
 * failure of both methods.
 */
boost::optional<std::string> getHomeDirectory();

/**
 * @brief Multi-platform implementation of chmod
 * @note There are issues with the ACL being ordered "incorrectly". This
 *        incorrect ordering does help with implementing the proper
 *        behaviors
 * 
 * This function approximates the functionality of the POSIX chmod function on
 * Windows. While there is the _chmod function on Windows, it does not support
 * the user, group, world permissions model. The Windows version of this
 * function will approximate it by using GetNamedSecurityInfoA to obtain the
 * file's owner and group. World is represented by the Everyone group on
 * Windows. Allowed permissions are represented by an access allowed access
 * control entry and unset permissions are represented by an explicit access
 * denied access control entry. However, the Windows preference for ACL ordering
 * creates some problems. For instance, if a user wishes to protect a file by
 * denying world access to a file, the normal standard for ACL ordering will end
 * up denying everyone, including the user, to the file (because of the deny
 * Everyone access control entry that is first in the ACL). To counter this, we
 * have to be more creative with the ACL order which presents some problems for
 * when attempting to modify permissions via File Explorer (complains of a
 * misordered ACL and offers to rectify the problem).
  */
bool platformChmod(const std::string& path, mode_t perms);

/**
 * @brief Multi-platform implementation of glob
 * @note glob support is not 100% congruent with Linux glob. There are slight
 *       differences in how GLOB_TILDE and GLOB_BRACE are implemented
 *
 * This function approximates the functionality of the POSIX glob function on
 * Windows. It has naive support of GLOB_TILDE (doesn't support ~user syntax),
 * GLOB_MARK, and GLOB_BRACE (custom translation of glob expressions to regex).
 */
std::vector<std::string> platformGlob(const std::string& find_path);

/**
 * @brief Checks to see if the current user has the permissions to perform a
 *        specified operation on a file
 *
 * This abstracts the POSIX access function across Windows and POSIX. On
 * Windows, this calls the equivalent _access function.
 */
int platformAccess(const std::string &path, mode_t mode);
}

