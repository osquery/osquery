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
#include <sys/stat.h>
#include <sys/types.h>

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#endif

#include <string>
#include <vector>

#include <boost/filesystem.hpp>
#include <boost/optional.hpp>

#include <osquery/status.h>

namespace fs = boost::filesystem;

namespace osquery {

#ifdef WIN32

using mode_t = int;
using ssize_t = SSIZE_T;
using PlatformHandle = HANDLE;
using PlatformTimeType = FILETIME;

// Windows do not define these by default
#define R_OK 4
#define W_OK 2
#define X_OK 1

// Windows does not define these constants, and they are neater
// than using raw octal for platformChmod, etc.
#define S_IRUSR 0400
#define S_IWUSR 0200
#define S_IXUSR 0100
#define S_IRWXU (S_IRUSR | S_IWUSR | S_IXUSR)

#define S_IRGRP (S_IRUSR >> 3)
#define S_IWGRP (S_IWUSR >> 3)
#define S_IXGRP (S_IXUSR >> 3)
#define S_IRWXG (S_IRWXU >> 3)

#define S_IROTH (S_IRGRP >> 3)
#define S_IWOTH (S_IWGRP >> 3)
#define S_IXOTH (S_IXGRP >> 3)
#define S_IRWXO (S_IRWXG >> 3)

#else

using PlatformHandle = int;
using PlatformTimeType = struct timeval;
#endif

typedef struct { PlatformTimeType times[2]; } PlatformTime;

/// Constant for an invalid handle.
const PlatformHandle kInvalidHandle = (PlatformHandle)-1;

/**
 * @brief File access modes for PlatformFile.
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
#define PF_OPEN_ALWAYS (3 << 2)
#define PF_TRUNCATE (4 << 2)

#define PF_NONBLOCK 0x0020
#define PF_APPEND 0x0040

/**
 * @brief Modes for seeking through a file.
 *
 * Provides a platform agnostic enumeration for file seek operations. These
 * are translated to the appropriate flags for the underlying platform.
 */
enum SeekMode { PF_SEEK_BEGIN = 0, PF_SEEK_CURRENT, PF_SEEK_END };

#ifdef WIN32
/// Takes a Windows FILETIME object and returns seconds since epoch
LONGLONG filetimeToUnixtime(const FILETIME& ft);

/**
 * @brief Stores information about the last Windows async request
 * @note Currently, we have rudimentary support for non-blocking operations
 *       on Windows. The implementation attempts to emulate POSIX non-blocking
 *       IO semantics using the Windows asynchronous API. As such, there are
 *       currently limitations. For example, opening a non-blocking file with
 *       read and write privileges may produce some problems. If a write
 *       operation does not immediately succeed, we cancel IO instead of
 *       waiting on it. As a result, on-going async read operations will get
 *       canceled and data might get lost.
 *
 * Windows-only class that deals with simulating POSIX asynchronous IO semantics
 * using Windows API calls
 */
struct AsyncEvent {
  AsyncEvent();
  ~AsyncEvent();

  OVERLAPPED overlapped_{0};
  std::unique_ptr<char[]> buffer_{nullptr};
  bool is_active_{false};
};

#endif

/**
 * @brief Platform-agnostic file object.
 *
 * PlatformFile is a multi-platform class that offers input/output capabilities
 * for files.
 */
class PlatformFile {
 public:
  explicit PlatformFile(const std::string& path, int mode, int perms = -1);
  explicit PlatformFile(PlatformHandle handle) : handle_(handle) {}

  PlatformFile(PlatformFile&& src) noexcept {
    handle_ = kInvalidHandle;
    std::swap(handle_, src.handle_);
  }

  ~PlatformFile();

  /// Checks to see if the file object is "special file".
  bool isSpecialFile() const;

  /**
   * @brief Checks to see if there are any pending IO operations.
   *
   * This is mostly used after a read()/write() error in non-blocking mode to
   * determine the intention of the error. If read()/write() returns an error
   * and hasPendingIo() is true, this indicates that the read()/write()
   * operation didn't complete on time.
   */
  bool hasPendingIo() const {
    return has_pending_io_;
  }

  /// Checks to see if the handle backing the PlatformFile object is valid.
  bool isValid() const {
    return (handle_ != kInvalidHandle);
  }

  /// Returns the platform specific handle.
  PlatformHandle nativeHandle() const {
    return handle_;
  }

  /**
   * @brief Returns success if owner of the file is root.
   * @note At the moment, we only determine that the owner of the current file
   *       is a member of the Administrators group. We do not count files owned
   *       by TrustedInstaller as owned by root.
   */
  Status isOwnerRoot() const;

  /// Returns success if the owner of the file is the current user.
  Status isOwnerCurrentUser() const;

  /// Determines whether the file has the executable bit set.
  Status isExecutable() const;

  /**
   * @brief Determines how immutable the file is to external modifications.
   * @note Currently, this is only implemented on Windows. The Windows version
   *       of this function ensures that writes are explicitly denied for the
   *       file AND the file's parent directory.
   */
  Status hasSafePermissions() const;

  bool getFileTimes(PlatformTime& times);

  bool setFileTimes(const PlatformTime& times);

  ssize_t read(void* buf, size_t nbyte);

  ssize_t write(const void* buf, size_t nbyte);

  off_t seek(off_t offset, SeekMode mode);

  size_t size() const;

 private:
  fs::path fname_;

  PlatformHandle handle_{kInvalidHandle};

  bool is_nonblock_{false};

  bool has_pending_io_{false};

#ifdef WIN32
  int cursor_{0};

  AsyncEvent last_read_;

  ssize_t getOverlappedResultForRead(void* buf, size_t requested_size);
#endif
};

/**
 * @brief Returns the current user's home directory.
 *
 * This uses multiple methods to find the current user's home directory. It
 * attempts to use environment variables first and on failure, tries to obtain
 * the path using platform specific functions. Returns a boost::none on the
 * failure of both methods.
 */
boost::optional<std::string> getHomeDirectory();

/**
 * @brief Multi-platform implementation of chmod.
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
 * mis-ordered ACL and offers to rectify the problem).
  */
bool platformChmod(const std::string& path, mode_t perms);

/**
 * @brief Multi-platform implementation of glob.
 * @note glob support is not 100% congruent with Linux glob. There are slight
 *       differences in how GLOB_TILDE and GLOB_BRACE are implemented.
 *
 * This function approximates the functionality of the POSIX glob function on
 * Windows. It has naive support of GLOB_TILDE (doesn't support ~user syntax),
 * GLOB_MARK, and GLOB_BRACE (custom translation of glob expressions to regex).
 */
std::vector<std::string> platformGlob(const std::string& find_path);

/**
 * @brief Checks to see if the current user has the permissions to perform a
 *        specified operation on a file.
 *
 * This abstracts the POSIX access function across Windows and POSIX. On
 * Windows, this calls the equivalent _access function.
 */
int platformAccess(const std::string& path, mode_t mode);

/**
 * @brief Checks to see if the provided directory is a temporary folder.
 * @note This just compares the temporary directory path against the given path
 *       on Windows.
 */
Status platformIsTmpDir(const fs::path& dir);

/// Determines the accessibility and existence of the file path.
Status platformIsFileAccessible(const fs::path& path);

/// Determine if the FILE object points to a tty (console, serial port, etc).
bool platformIsatty(FILE* f);

/// Opens a file and returns boost::none on error
boost::optional<FILE*> platformFopen(const std::string& filename,
                                     const std::string& mode);

/**
 * @brief Checks for the existence of a named pipe or UNIX socket.
 *
 * This method is overloaded to perform two actions. If removal is requested
 * the success is determined based on the non-existence or successful removal
 * of the socket path. Otherwise the result is straightforward.
 *
 * The removal action is only used when extensions or the extension manager
 * is first starting.
 *
 * @param path The filesystem path to a UNIX socket or Windows named pipe.
 * @param remove_socket Attempt to remove the socket if it exists.
 *
 * @return Success if the socket exists and removal was not requested. False
 * if the socket exists and removal was requested (and the attempt to remove
 * had failed).
 */
Status socketExists(const fs::path& path, bool remove_socket = false);

/**
* @brief Returns the OS root system directory.
*
* Some applications store configuration and application data inside of the
* Windows directory. This function retrieves the path to the current
* configurations Windows location.
*
* On POSIX systems this returns "/".
*
* @return an instance of fs::path, containing the OS root location.
*/
boost::filesystem::path getSystemRoot();
}
