/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <AclAPI.h>
#include <io.h>
#include <sddl.h>
#include <ShlObj.h>

#include <memory>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

#include <boost/filesystem.hpp>
#include <boost/optional.hpp>

#include "osquery/core/process.h"
#include "osquery/filesystem/fileops.h"

namespace fs = boost::filesystem;

namespace osquery {

#define S_IRUSR 0400
#define S_IWUSR 0200
#define S_IXUSR 0100
#define S_IRGRP 0040
#define S_IWGRP 0020
#define S_IXGRP 0010
#define S_IROTH 0004
#define S_IWOTH 0002
#define S_IXOTH 0001

#define CHMOD_READ    SYNCHRONIZE | READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_READ_EA | FILE_READ_DATA
#define CHMOD_WRITE   FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE
#define CHMOD_EXECUTE FILE_EXECUTE 

using AclObject = std::unique_ptr<unsigned char[]>;

class WindowsFindFiles {
 public:
  explicit WindowsFindFiles(const fs::path& path) : path_(path) {
    handle_ = ::FindFirstFileA(path_.make_preferred().string().c_str(), &fd_);
  }

  ~WindowsFindFiles() {
    if (handle_ != INVALID_HANDLE_VALUE) {
      ::FindClose(handle_);
      handle_ = INVALID_HANDLE_VALUE;
    }
  }

  std::vector<fs::path> get() {
    std::vector<fs::path> results;

    if (handle_ != INVALID_HANDLE_VALUE) {
      do {
        std::string component(fd_.cFileName);
        if (component != "." && component != "..") {
          if (path_.has_parent_path()) {
            results.push_back(path_.parent_path() / component);
          } else {
            results.push_back(fs::path(component));
          }
        }

        ::RtlZeroMemory(&fd_, sizeof(fd_));
      } while (::FindNextFileA(handle_, &fd_));
    }

    return results;
  }

  std::vector<fs::path> getDirectories() {
    std::vector<fs::path> results;
    for (auto const& result : get()) {
      if (fs::is_directory(result)) {
        results.push_back(result);
      }
    }
    return results;
  }

 private:
  HANDLE handle_{INVALID_HANDLE_VALUE};
  WIN32_FIND_DATAA fd_{0};

  fs::path path_;
};

static bool hasGlobBraces(const std::string& glob) {
  int brace_depth = 0;
  bool has_brace = false;

  for (size_t i = 0; i < glob.size(); i++) {
    switch (glob[i]) {
      case '{':
        brace_depth += 1;
        has_brace = true;
        break;
      case '}':
        brace_depth -= 1;
        break;
      default:
        break;
    }
  }
  return (brace_depth == 0 && has_brace);
}

AsyncEvent::AsyncEvent() {
  overlapped_.hEvent = ::CreateEventA(NULL, FALSE, FALSE, NULL);
}

AsyncEvent::~AsyncEvent() {
  if (overlapped_.hEvent != NULL) {
    ::CloseHandle(overlapped_.hEvent);
  }
}

// Inspired by glob-to-regexp node package
static std::string globToRegex(const std::string &glob) {
  bool in_group = false;
  std::string regex("^");

  for (size_t i = 0; i < glob.size(); i++) {
    char c = glob[i];

    switch (c) {
      case '\\':
      case '/':
      case '$':
      case '^':
      case '+':
      case '.':
      case '(':
      case ')':
      case '=':
      case '!':
      case '|':
        regex += "\\";
        regex += c;
        break;
      case '?':
        regex += ".";
        break;
      case '[':
      case ']':
        regex += c;
        break;
      case '{':
        in_group = true;
        regex += "(";
        break;
      case '}':
        in_group = false;
        regex += ")";
        break;
      case ',':
        regex += "|";
        break;
      case '*':
        regex += ".*";
        break;
      default:
        regex += c;
        break;
    }
  }

  return regex + "$";
}

static DWORD getNewAclSize(PACL dacl, PSID sid, ACL_SIZE_INFORMATION& info,
                           bool needs_allowed, bool needs_denied) {
  // This contains the current buffer size of dacl
  DWORD acl_size = info.AclBytesInUse;

  // By default, we assume that the ACL as pointed to by the dacl arugment does
  // not contain any access control entries (further known as ACE) associated
  // with sid. If we require an access allowed and/or access denied ACE, we will
  // increment acl_size by the size of the new ACE.

  if (needs_allowed) {
    acl_size +=
        sizeof(ACCESS_ALLOWED_ACE) + ::GetLengthSid(sid) - sizeof(DWORD);
  }

  if (needs_denied) {
    acl_size += sizeof(ACCESS_DENIED_ACE) + ::GetLengthSid(sid) - sizeof(DWORD);
  }

  // Enumerate the current ACL looking for ACEs associated with sid. Since our
  // assumption is that such a sid does not exist, we need to subtract their
  // size from acl_size if found.
  PACE_HEADER entry = nullptr;
  for (DWORD i = 0; i < info.AceCount; i++) {
    if (!::GetAce(dacl, i, (LPVOID *)&entry)) {
      return 0;
    }

    if (entry->AceType == ACCESS_ALLOWED_ACE_TYPE &&
        ::EqualSid(sid, &((ACCESS_ALLOWED_ACE *)entry)->SidStart)) {
      acl_size -=
          sizeof(ACCESS_ALLOWED_ACE) + ::GetLengthSid(sid) - sizeof(DWORD);
    }

    if (entry->AceType == ACCESS_DENIED_ACE_TYPE &&
        ::EqualSid(sid, &((ACCESS_DENIED_ACE *)entry)->SidStart)) {
      acl_size -=
          sizeof(ACCESS_DENIED_ACE) + ::GetLengthSid(sid) - sizeof(DWORD);
    }

    // We don't care about inherited ACEs
    if ((entry->AceFlags & INHERITED_ACE) == INHERITED_ACE) {
      break;
    }
  }

  return acl_size;
}

static AclObject modifyAcl(PACL acl, PSID target, bool allow_read,
                           bool allow_write, bool allow_exec) {
  if (acl == nullptr || !::IsValidAcl(acl) || target == nullptr ||
      !::IsValidSid(target)) {
    return std::move(AclObject());
  }

  DWORD allow_mask = 0;
  DWORD deny_mask = 0;

  ACL_SIZE_INFORMATION info = { 0 };
  info.AclBytesInUse = sizeof(ACL);

  if (!::GetAclInformation(acl, &info, sizeof(info), AclSizeInformation)) {
    return std::move(AclObject());
  }

  // We have defined CHMOD_READ, CHMOD_WRITE, and CHMOD_EXECUTE as combinations
  // of Windows access masks in order to simulate the intended effects of the r,
  // w, x permissions of POSIX. In order to correctly simulate the permissions,
  // any permissions set will be explicitly allowed and any permissions that are
  // unset are explicitly denied. This is all done via access allowed and access
  // denied ACEs.

  if (allow_read) {
    allow_mask = CHMOD_READ;
  } else {
    deny_mask = CHMOD_READ;
  }

  if (allow_write) {
    allow_mask |= CHMOD_WRITE;
  } else {
    deny_mask |= CHMOD_WRITE;
  }

  if (allow_exec) {
    allow_mask |= CHMOD_EXECUTE;
  } else {
    deny_mask |= CHMOD_EXECUTE;
  }

  DWORD new_acl_size = 0;
  if (allow_read && allow_write && allow_exec) {
    new_acl_size = getNewAclSize(acl, target, info, true, false);
  } else if (!allow_read && !allow_write && !allow_exec) {
    new_acl_size = getNewAclSize(acl, target, info, false, true);
  } else {
    new_acl_size = getNewAclSize(acl, target, info, true, true);
  }

  AclObject new_acl_buffer(new unsigned char[new_acl_size]);
  PACL new_acl = reinterpret_cast<PACL>(new_acl_buffer.get());

  if (!::InitializeAcl(new_acl, new_acl_size, ACL_REVISION)) {
    return std::move(AclObject());
  }

  // Enumerate through the old ACL and copy over all the non-relevant ACEs
  // (read: ACEs that are inherited and not associated with the specified sid).
  // We disregard the ACEs associated with our sid in the old ACL and replace
  // them with updated access masks.
  //
  // The curious bit here is how we order things. In normal Windows ACLs, the
  // ACEs are ordered in a fashion where access denied ACEs have priority to
  // access allowed ACEs. While this is a strong policy, this doesn't fit into
  // our use case and in fact, hurts it. Setting 0600 would prevent even the
  // owner from reading/writing! To counter this, we selectively order the ACEs
  // in our new ACL to fit our needs. This will generate complaints with tools
  // that deal with viewing or modifying the ACL (such as File Explorer).

  DWORD i = 0;
  PACE_HEADER entry = nullptr;
  for (i = 0; i < info.AceCount; i++) {
    if (!::GetAce(acl, i, (LPVOID *)&entry)) {
      return std::move(AclObject());
    }

    if ((entry->AceFlags & INHERITED_ACE) == INHERITED_ACE) {
      break;
    }

    if ((entry->AceType == ACCESS_ALLOWED_ACE_TYPE &&
      ::EqualSid(target, &((ACCESS_ALLOWED_ACE *)entry)->SidStart)) ||
      (entry->AceType == ACCESS_DENIED_ACE_TYPE &&
        ::EqualSid(target, &((ACCESS_DENIED_ACE *)entry)->SidStart))) {
      continue;
    }

    if (!::AddAce(new_acl, ACL_REVISION, MAXDWORD, (LPVOID)entry, entry->AceSize)) {
      return std::move(AclObject());
    }
  }

  if (deny_mask != 0 &&
    !::AddAccessDeniedAce(new_acl, ACL_REVISION, deny_mask, target)) {
    return std::move(AclObject());
  }

  if (allow_mask != 0 &&
    !::AddAccessAllowedAce(new_acl, ACL_REVISION, allow_mask, target)) {
    return std::move(AclObject());
  }

  for (; i < info.AceCount; i++) {
    if (!::GetAce(acl, i, (LPVOID *)&entry)) {
      return std::move(AclObject());
    }

    if (!::AddAce(new_acl, ACL_REVISION, MAXDWORD, (LPVOID)entry, entry->AceSize)) {
      return std::move(AclObject());
    }
  }

  return std::move(new_acl_buffer);
}

PlatformFile::PlatformFile(const std::string& path, int mode, int perms) {
  DWORD access_mask = 0;
  DWORD flags_and_attrs = 0;
  DWORD creation_disposition = 0;
  std::unique_ptr<SECURITY_ATTRIBUTES> security_attrs;

  if ((mode & PF_READ) == PF_READ) {
    access_mask |= GENERIC_READ;
  }

  if ((mode & PF_WRITE) == PF_WRITE) {
    access_mask |= GENERIC_WRITE;
  }

  switch (PF_GET_OPTIONS(mode)) {
    case PF_GET_OPTIONS(PF_CREATE_NEW):
      creation_disposition = CREATE_NEW;
      break;
    case PF_GET_OPTIONS(PF_CREATE_ALWAYS):
      creation_disposition = CREATE_ALWAYS;
      break;
    case PF_GET_OPTIONS(PF_OPEN_EXISTING):
      creation_disposition = OPEN_EXISTING;
      break;
    case PF_GET_OPTIONS(PF_TRUNCATE):
      creation_disposition = TRUNCATE_EXISTING;
      break;
    default:
      break;
  }

  if ((mode & PF_NONBLOCK) == PF_NONBLOCK) {
    flags_and_attrs |= FILE_FLAG_OVERLAPPED;
    is_nonblock_ = true;
  }

  if (perms != -1) {
    /// TODO(#2001): set up a security descriptor based off the perms
  }

  handle_ = ::CreateFileA(path.c_str(), access_mask, 0,
                          security_attrs.get(), creation_disposition,
                          flags_and_attrs, nullptr);
}

PlatformFile::~PlatformFile() {
  if (handle_ != kInvalidHandle && handle_ != nullptr) {
    ::CancelIo(handle_);
    ::CloseHandle(handle_);
    handle_ = kInvalidHandle;
  }
}

bool PlatformFile::isFile() const {
  return (::GetFileType(handle_) == FILE_TYPE_DISK);
}

bool PlatformFile::isOwnerRoot() const {
  // TODO(#2001): mark as false for now
  return false;
}

bool PlatformFile::getFileTimes(PlatformTime& times) {
  if (!isValid()) {
    return false;
  }

  return (::GetFileTime(handle_, nullptr, &times.times[0], &times.times[1]) != FALSE);
}

bool PlatformFile::setFileTimes(const PlatformTime& times) {
  if (!isValid()) {
    return false;
  }

  return (::SetFileTime(handle_, nullptr, &times.times[0], &times.times[1]) != FALSE);
}

ssize_t PlatformFile::getOverlappedResultForRead(void *buf,
                                                 size_t requested_size) {
  ssize_t nret = 0;
  DWORD bytes_read = 0;
  DWORD last_error = 0;

  if (::GetOverlappedResultEx(handle_, &last_read_.overlapped_, &bytes_read, 0,
                              TRUE)) {
    // Read operation has finished

    // NOTE: We do NOT support situations where the second read operation uses a
    // SMALLER buffer than the initial async request. This will cause the
    // smaller amount to be copied and truncate DATA!
    DWORD size = min(requested_size, bytes_read);
    ::memcpy_s(buf, requested_size, last_read_.buffer_.get(), size);

    // Update our cursor
    cursor_ += bytes_read;

    has_pending_io_ = false;
    last_read_.is_active_ = false;
    last_read_.buffer_.reset(nullptr);
    nret = size;
  } else {
    last_error = ::GetLastError();
    if (last_error == ERROR_IO_INCOMPLETE) {
      // Read operation has still not completed
      has_pending_io_ = true;
      last_read_.is_active_ = true;
      nret = -1;
    } else {
      // Error has occurred, just in case, cancel all IO
      ::CancelIo(handle_);

      has_pending_io_ = false;
      last_read_.is_active_ = false;
      last_read_.buffer_.reset(nullptr);
      nret = -1;
    }
  }
  return nret;
}

ssize_t PlatformFile::read(void *buf, size_t nbyte) {
  if (!isValid()) {
    return -1;
  }

  ssize_t nret = 0;
  DWORD bytes_read = 0;
  DWORD last_error = 0;
  
  has_pending_io_ = false;

  if (is_nonblock_) {
    if (last_read_.is_active_) {
      nret = getOverlappedResultForRead(buf, nbyte);
    } else {
      last_read_.overlapped_.Offset = cursor_;
      last_read_.buffer_.reset(new char[nbyte]);

      if (!::ReadFile(handle_, last_read_.buffer_.get(), nbyte, NULL, &last_read_.overlapped_)) {
        last_error = ::GetLastError();
        if (last_error == ERROR_IO_PENDING || last_error == ERROR_MORE_DATA) {
          nret = getOverlappedResultForRead(buf, nbyte);
        } else {
          nret = -1;
        }
      } else {
        // This should never occur
        nret = -1;
      }
    }
  } else {
    if (!::ReadFile(handle_, buf, nbyte, &bytes_read, nullptr)) {
      nret = -1;
    } else {
      nret = bytes_read;
    }
  }

  return nret;
}

ssize_t PlatformFile::write(const void *buf, size_t nbyte) {
  if (!isValid()) {
    return -1;
  }

  ssize_t nret = 0;
  DWORD bytes_written = 0;
  DWORD last_error = 0;
  
  has_pending_io_ = false;

  if (is_nonblock_) {
    AsyncEvent write_event;
    if (!::WriteFile(handle_, buf, nbyte, &bytes_written, &write_event.overlapped_)) {
      last_error = ::GetLastError();
      if (last_error == ERROR_IO_PENDING) {
        if (!::GetOverlappedResultEx(handle_, &write_event.overlapped_, &bytes_written, 0, TRUE)) {
          last_error = ::GetLastError();
          if (last_error == ERROR_IO_INCOMPLETE) {
            has_pending_io_ = true;
            // If the write operation has not succeeded, cancel it
            ::CancelIo(handle_);
            nret = -1;
          } else {
            // Error of unknown origin
            nret = -1;
          }
        } else {
          // Write operation succeeded
          nret = bytes_written;
        }
      } else {
        nret = -1;
      }
    } else {
      // This should not occur...
      nret = -1;
    }
  } else {
    if (!::WriteFile(handle_, buf, nbyte, &bytes_written, nullptr)) {
      nret = -1;
    } else {
      nret = bytes_written;
    }
  }

  return nret;
}

off_t PlatformFile::seek(off_t offset, SeekMode mode) {
  if (!isValid()) {
    return -1;
  }
  
  DWORD whence = 0;
  switch (mode) {
    case PF_SEEK_BEGIN:
      whence = FILE_BEGIN;
      break;
    case PF_SEEK_CURRENT:
      whence = FILE_CURRENT;
      break;
    case PF_SEEK_END:
      whence = FILE_END;
      break;
    default:
      break;
  }

  cursor_ = ::SetFilePointer(handle_, offset, nullptr, whence);
  return cursor_;
}

size_t PlatformFile::size() const {
  return ::GetFileSize(handle_, nullptr);
}

bool platformChmod(const std::string& path, mode_t perms) {
  DWORD ret = 0;
  PACL dacl = nullptr;
  PSID owner = nullptr;
  PSID group = nullptr;

  ret = ::GetNamedSecurityInfoA(path.c_str(), SE_FILE_OBJECT,
                                OWNER_SECURITY_INFORMATION |
                                    GROUP_SECURITY_INFORMATION |
                                    DACL_SECURITY_INFORMATION,
                                &owner, &group, &dacl, nullptr, nullptr);

  if (ret != ERROR_SUCCESS) {
    return false;
  }

  if (owner == nullptr || group == nullptr || dacl == nullptr) {
    return false;
  }

  DWORD sid_size = SECURITY_MAX_SID_SIZE;
  std::vector<char> world_buf(sid_size);
  PSID world = &world_buf[0];

  if (!::CreateWellKnownSid(WinWorldSid, nullptr, world, &sid_size)) {
    return false;
  }

  PACL acl = nullptr;
  AclObject acl_buffer =
      modifyAcl(dacl, owner, (perms & S_IRUSR) == S_IRUSR,
                (perms & S_IWUSR) == S_IWUSR, (perms & S_IXUSR) == S_IXUSR);
  acl = reinterpret_cast<PACL>(acl_buffer.get());

  if (acl == nullptr) {
    return false;
  }

  acl_buffer =
      modifyAcl(acl, group, (perms & S_IRGRP) == S_IRGRP,
                (perms & S_IWGRP) == S_IWGRP, (perms & S_IXGRP) == S_IXGRP);
  acl = reinterpret_cast<PACL>(acl_buffer.get());

  if (acl == nullptr) {
    return false;
  }

  acl_buffer =
      modifyAcl(acl, world, (perms & S_IROTH) == S_IROTH,
                (perms & S_IWOTH) == S_IWOTH, (perms & S_IXOTH) == S_IXOTH);
  acl = reinterpret_cast<PACL>(acl_buffer.get());

  if (acl == nullptr) {
    return false;
  }

  // SetNamedSecurityInfoA takes a mutable string for the path parameter
  std::vector<char> mutable_path(path.begin(), path.end());
  mutable_path.push_back('\0');

  if (::SetNamedSecurityInfoA(&mutable_path[0], SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION, NULL, NULL, acl,
                              NULL) != ERROR_SUCCESS) {
    return false;
  }

  return true;
}

std::vector<std::string> platformGlob(const std::string& find_path) {
  fs::path full_path(find_path);

  // This is a naive implementation of GLOB_TILDE. If the first two characters
  // in the path are '~/' or '~\', we replace it with the value of the
  // USERPROFILE environment variable.
  if (find_path.size() >= 2 && find_path[0] == '~' &&
      (find_path[1] == '/' || find_path[1] == '\\')) {
    auto homedir = getEnvVar("USERPROFILE");
    if (homedir.is_initialized()) {
      full_path = fs::path(*homedir) / find_path.substr(2);
    }
  }
  
  std::regex pattern(".*[*\?].*");

  // This vector will contain all the valid paths at each stage of the
  std::vector<fs::path> valid_paths;
  valid_paths.push_back(fs::path(""));
  
  if (full_path.has_parent_path()) {
    // The provided glob pattern contains more than one directory to traverse.
    // We enumerate each component in the path to generate a list of all
    // possible directories that we need to perform our glob pattern match.
    for (auto &component : full_path.parent_path()) {
      std::vector<fs::path> tmp_valid_paths;

      // This will enumerate the old set of valid paths and update it by looking
      // for directories matching the specified glob pattern. 
      for (auto const &valid_path : valid_paths) {
        if (hasGlobBraces(component.string())) {
          // If the component contains braces, we convert the component into a
          // regex, enumerate through all the directories in the current
          // directory and only mark the ones fitting the regex pattern as
          // valid.
          std::regex component_pattern(globToRegex(component.string()));
          WindowsFindFiles wf(valid_path / "*");
          for (auto const& file_path : wf.getDirectories()) {
            if (std::regex_match(file_path.filename().string(), component_pattern)) {
              tmp_valid_paths.push_back(file_path);
            }
          }
        } else if (std::regex_match(component.string(), pattern)) {
          // If the component contains wildcard characters such as * or ?, we
          // pass the pattern into the Windows FindFirstFileA function to get a
          // list of valid directories.
          WindowsFindFiles wf(valid_path / component);
          for (auto const& result : wf.getDirectories()) {
            tmp_valid_paths.push_back(result);
          }
        } else {
          // Since there are no braces and other glob-like wildcards, we are
          // going to append the component to the previous valid path and append
          // the new path to the list
          if (fs::exists(valid_path / component)) {
            tmp_valid_paths.push_back(valid_path / component);
          }
        }
      }
      valid_paths.swap(tmp_valid_paths);
    }
  }

  std::vector<std::string> results;

  // After generating all the valid directories, we enumerate the valid paths
  // and instead of getting back all the glob pattern matching directories, we
  // unrestrict it to get back files as well. We append the file names to the
  // valid paths are return the list.
  for (auto const &valid_path : valid_paths) {
    if (hasGlobBraces(full_path.filename().string())) {
      std::regex component_pattern(globToRegex(full_path.filename().string()));
      WindowsFindFiles wf(valid_path / "*");
      for (auto& result : wf.get()) {
        if (std::regex_match(result.filename().string(), component_pattern)) {
          auto result_path = result.make_preferred().string();
          if (fs::is_directory(result)) {
            result_path += "\\";
          }
          results.push_back(result_path);
        }
      }
    } else {
      WindowsFindFiles wf(valid_path / full_path.filename());
      for (auto& result : wf.get()) {
        auto result_path = result.make_preferred().string();
        if (fs::is_directory(result)) {
          result_path += "\\";
        }
        results.push_back(result_path);
      }
    }
  }

  return results;
}

boost::optional<std::string> getHomeDirectory() {
  std::vector<char> profile(MAX_PATH);
  auto value = getEnvVar("USERPROFILE");
  if (value.is_initialized()) {
    return *value;
  } else if (SUCCEEDED(::SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, &profile[0]))) {
    return std::string(&profile[0]);
  } else {
    return boost::none;
  }
}

int platformAccess(const std::string& path, int mode) {
  return _access(path.c_str(), mode);
}
}

