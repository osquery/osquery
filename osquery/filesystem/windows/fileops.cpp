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
#include <LM.h>
#include <ShlObj.h>
#include <Shlwapi.h>
#include <io.h>
#include <sddl.h>

#include <memory>
#include <regex>
#include <vector>

#include <boost/filesystem.hpp>
#include <boost/optional.hpp>

#include <osquery/logger.h>

#include "osquery/core/process.h"
#include "osquery/filesystem/fileops.h"

#define min(a,b)            (((a) < (b)) ? (a) : (b))
#define max(a,b)            (((a) > (b)) ? (a) : (b))

namespace fs = boost::filesystem;
namespace errc = boost::system::errc;

namespace osquery {

/*
 * Avoid having the same right being used in multiple CHMOD_* macros. Doing so
 * will cause issues when requesting certain permissions in the presence of deny
 * access control entries
 */
#define CHMOD_READ (FILE_READ_DATA | FILE_READ_EA)
#define CHMOD_WRITE                                                            \
  (FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA | FILE_WRITE_EA)
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
    boost::system::error_code ec;

    for (auto const& result : get()) {
      ec.clear();
      if (fs::is_directory(result, ec) && ec.value() == errc::success) {
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
  overlapped_.hEvent = ::CreateEventA(nullptr, FALSE, FALSE, nullptr);
}

AsyncEvent::~AsyncEvent() {
  if (overlapped_.hEvent != nullptr) {
    ::CloseHandle(overlapped_.hEvent);
  }
}

// Inspired by glob-to-regexp node package
static std::string globToRegex(const std::string& glob) {
  bool in_group = false;
  std::string regex("^");

  for (size_t i = 0; i < glob.size(); i++) {
    char c = glob[i];

    switch (c) {
    case '?':
      regex += '.';
      break;
    case '{':
      in_group = true;
      regex += '(';
      break;
    case '}':
      in_group = false;
      regex += ')';
      break;
    case ',':
      regex += '|';
      break;
    case '*':
      regex += ".*";
      break;
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
      regex += '\\';
    default:
      regex += c;
      break;
    }
  }

  return regex + "$";
}

static DWORD getNewAclSize(PACL dacl,
                           PSID sid,
                           ACL_SIZE_INFORMATION& info,
                           bool needs_allowed,
                           bool needs_denied) {
  // This contains the current buffer size of dacl
  DWORD acl_size = info.AclBytesInUse;

  /*
   * By default, we assume that the ACL as pointed to by the dacl arugment does
   * not contain any access control entries (further known as ACE) associated
   * with sid. If we require an access allowed and/or access denied ACE, we will
   * increment acl_size by the size of the new ACE.
   */

  if (needs_allowed) {
    acl_size +=
        sizeof(ACCESS_ALLOWED_ACE) + ::GetLengthSid(sid) - sizeof(DWORD);
  }

  if (needs_denied) {
    acl_size += sizeof(ACCESS_DENIED_ACE) + ::GetLengthSid(sid) - sizeof(DWORD);
  }

  /*
   * Enumerate the current ACL looking for ACEs associated with sid. Since our
   * assumption is that such a sid does not exist, we need to subtract their
   * size from acl_size if found.
   */
  PACE_HEADER entry = nullptr;
  for (DWORD i = 0; i < info.AceCount; i++) {
    if (!::GetAce(dacl, i, (LPVOID*)&entry)) {
      return 0;
    }

    // We don't care about inherited ACEs
    if ((entry->AceFlags & INHERITED_ACE) == INHERITED_ACE) {
      break;
    }

    if (entry->AceType == ACCESS_ALLOWED_ACE_TYPE &&
        ::EqualSid(sid, &((ACCESS_ALLOWED_ACE*)entry)->SidStart)) {
      acl_size -=
          sizeof(ACCESS_ALLOWED_ACE) + ::GetLengthSid(sid) - sizeof(DWORD);
    }

    if (entry->AceType == ACCESS_DENIED_ACE_TYPE &&
        ::EqualSid(sid, &((ACCESS_DENIED_ACE*)entry)->SidStart)) {
      acl_size -=
          sizeof(ACCESS_DENIED_ACE) + ::GetLengthSid(sid) - sizeof(DWORD);
    }
  }

  return acl_size;
}

static Status checkAccessWithSD(PSECURITY_DESCRIPTOR sd, mode_t mode) {
  BOOL status = FALSE;
  DWORD access_rights = 0;
  HANDLE process_token = INVALID_HANDLE_VALUE;
  HANDLE impersonate_token = INVALID_HANDLE_VALUE;

  if ((mode & R_OK) == R_OK) {
    access_rights = GENERIC_READ;
  }

  if ((mode & W_OK) == W_OK) {
    access_rights |= GENERIC_WRITE;
  }

  if ((mode & X_OK) == X_OK) {
    access_rights |= GENERIC_EXECUTE;
  }

  status = ::OpenProcessToken(
      ::GetCurrentProcess(),
      TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_DUPLICATE | STANDARD_RIGHTS_READ,
      &process_token);
  if (!status) {
    return Status(-1, "OpenProcessToken failed");
  }

  status = ::DuplicateToken(
      process_token, SecurityImpersonation, &impersonate_token);
  ::CloseHandle(process_token);

  if (!status) {
    return Status(-1, "DuplicateToken failed");
  }

  GENERIC_MAPPING mapping = {static_cast<ACCESS_MASK>(-1),
                             static_cast<ACCESS_MASK>(-1),
                             static_cast<ACCESS_MASK>(-1),
                             static_cast<ACCESS_MASK>(-1)};
  PRIVILEGE_SET privileges = {0};

  BOOL access_status = FALSE;
  DWORD granted_access = 0;
  DWORD privileges_length = sizeof(privileges);

  mapping.GenericRead = FILE_GENERIC_READ;
  mapping.GenericWrite = FILE_GENERIC_WRITE;
  mapping.GenericExecute = FILE_GENERIC_EXECUTE;
  mapping.GenericAll = FILE_ALL_ACCESS;

  ::MapGenericMask(&access_rights, &mapping);

  status = ::AccessCheck(sd,
                         impersonate_token,
                         access_rights,
                         &mapping,
                         &privileges,
                         &privileges_length,
                         &granted_access,
                         &access_status);
  ::CloseHandle(impersonate_token);

  if (!status) {
    return Status(-1, "AccessCheck failed");
  }

  if (access_status) {
    return Status(0, "OK");
  }

  return Status(1, "Bad mode for file");
}

static Status hasAccess(const fs::path& path, mode_t mode) {
  DWORD result = -1;
  PSECURITY_DESCRIPTOR sd = nullptr;
  SECURITY_INFORMATION security_info = OWNER_SECURITY_INFORMATION |
                                       GROUP_SECURITY_INFORMATION |
                                       DACL_SECURITY_INFORMATION;

  result = ::GetNamedSecurityInfoW(path.wstring().c_str(),
                                   SE_FILE_OBJECT,
                                   security_info,
                                   nullptr,
                                   nullptr,
                                   nullptr,
                                   nullptr,
                                   &sd);
  if (result != ERROR_SUCCESS) {
    return Status(-1, "GetNamedSecurityInfo failed: " + std::to_string(result));
  }

  auto status = checkAccessWithSD(sd, mode);
  ::LocalFree(sd);

  return status;
}

static Status hasAccess(HANDLE handle, mode_t mode) {
  BOOL status = FALSE;
  DWORD sd_size = 0;
  SECURITY_INFORMATION security_info = OWNER_SECURITY_INFORMATION |
                                       GROUP_SECURITY_INFORMATION |
                                       DACL_SECURITY_INFORMATION;

  status =
      ::GetUserObjectSecurity(handle, &security_info, nullptr, 0, &sd_size);
  if (status || (!status && ::GetLastError() != ERROR_INSUFFICIENT_BUFFER)) {
    return Status(-1, "GetUserObjectSecurity get SD size error");
  }

  std::vector<char> sd_buffer;
  sd_buffer.assign(sd_size, '\0');

  PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)sd_buffer.data();
  status =
      ::GetUserObjectSecurity(handle, &security_info, sd, sd_size, &sd_size);
  if (!status) {
    return Status(-1, "GetUserObjectSecurity failed");
  }

  return checkAccessWithSD(sd, mode);
}

static AclObject modifyAcl(PACL acl,
                           PSID target,
                           bool allow_read,
                           bool allow_write,
                           bool allow_exec,
                           bool target_is_owner = false) {
  if (acl == nullptr || !::IsValidAcl(acl) || target == nullptr ||
      !::IsValidSid(target)) {
    return std::move(AclObject());
  }

  /*
   * On POSIX, all users can view the owner, group, world permissions of a file.
   * To mimic this behavior on Windows, we give READ_CONTROL permissions to
   * everyone. READ_CONTROL allows for an user to read the target file's DACL.
   */
  DWORD allow_mask = READ_CONTROL;
  DWORD deny_mask = 0;

  ACL_SIZE_INFORMATION info = {0};
  info.AclBytesInUse = sizeof(ACL);

  if (!::GetAclInformation(acl, &info, sizeof(info), AclSizeInformation)) {
    return std::move(AclObject());
  }

  if (target_is_owner) {
    /*
     * Owners should always have the ability to delete the target file and
     * modify the target file's DACL--at least this appears to be the case for
     * POSIX.
     */
    allow_mask |= DELETE | WRITE_DAC;
  }

  /*
   * We have defined CHMOD_READ, CHMOD_WRITE, and CHMOD_EXECUTE as combinations
   * of Windows access masks in order to simulate the intended effects of the r,
   * w, x permissions of POSIX. In order to correctly simulate the permissions,
   * any permissions set will be explicitly allowed and any permissions that are
   * unset are explicitly denied. This is all done via access allowed and access
   * denied ACEs.
   *
   * We add additional rights for allow cases because we do not want to pollute
   * the CHMOD_* with overlapping rights. For instance, adding SYNCHRONIZE to
   * both CHMOD_READ and CHMOD_EXECUTE will be problematic if execute is denied.
   * SYNCHRONIZE will be added to a deny access control entry which will prevent
   * even a GENERIC_READ from occurring.
   */

  if (allow_read) {
    allow_mask |= CHMOD_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
  } else {
    deny_mask |= CHMOD_READ;
  }

  if (allow_write) {
    allow_mask |= CHMOD_WRITE | DELETE | SYNCHRONIZE;
  } else {
    // Only deny DELETE if the principal is not the owner
    if (!target_is_owner) {
      deny_mask |= DELETE;
    }

    deny_mask |= CHMOD_WRITE;
  }

  if (allow_exec) {
    allow_mask |= CHMOD_EXECUTE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
  } else {
    deny_mask |= CHMOD_EXECUTE;
  }

  // Only if r and x are denied do we deny FILE_READ_ATTRIBUTES
  if (!allow_read && !allow_exec) {
    deny_mask |= FILE_READ_ATTRIBUTES;
  }

  DWORD new_acl_size = 0;
  if (allow_read && allow_write && allow_exec) {
    new_acl_size = getNewAclSize(acl, target, info, true, false);
  } else {
    new_acl_size = getNewAclSize(acl, target, info, true, true);
  }

  AclObject new_acl_buffer(new unsigned char[new_acl_size]);
  PACL new_acl = reinterpret_cast<PACL>(new_acl_buffer.get());

  if (!::InitializeAcl(new_acl, new_acl_size, ACL_REVISION)) {
    return std::move(AclObject());
  }

  /*
   * Enumerate through the old ACL and copy over all the non-relevant ACEs
   * (read: ACEs that are inherited and not associated with the specified sid).
   * We disregard the ACEs associated with our sid in the old ACL and replace
   * them with updated access masks.
   *
   * The curious bit here is how we order things. In normal Windows ACLs, the
   * ACEs are ordered in a fashion where access denied ACEs have priority to
   * access allowed ACEs. While this is a strong policy, this doesn't fit into
   * our use case and in fact, hurts it. Setting 0600 would prevent even the
   * owner from reading/writing! To counter this, we selectively order the ACEs
   * in our new ACL to fit our needs. This will generate complaints with tools
   * that deal with viewing or modifying the ACL (such as File Explorer).
   */

  DWORD i = 0;
  PACE_HEADER entry = nullptr;
  for (i = 0; i < info.AceCount; i++) {
    if (!::GetAce(acl, i, (LPVOID*)&entry)) {
      return std::move(AclObject());
    }

    if ((entry->AceFlags & INHERITED_ACE) == INHERITED_ACE) {
      break;
    }

    if ((entry->AceType == ACCESS_ALLOWED_ACE_TYPE &&
         ::EqualSid(target, &((ACCESS_ALLOWED_ACE*)entry)->SidStart)) ||
        (entry->AceType == ACCESS_DENIED_ACE_TYPE &&
         ::EqualSid(target, &((ACCESS_DENIED_ACE*)entry)->SidStart))) {
      continue;
    }

    if (!::AddAce(
            new_acl, ACL_REVISION, MAXDWORD, (LPVOID)entry, entry->AceSize)) {
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
    if (!::GetAce(acl, i, (LPVOID*)&entry)) {
      return std::move(AclObject());
    }

    if (!::AddAce(
            new_acl, ACL_REVISION, MAXDWORD, (LPVOID)entry, entry->AceSize)) {
      return std::move(AclObject());
    }
  }

  return std::move(new_acl_buffer);
}

PlatformFile::PlatformFile(const std::string& path, int mode, int perms)
    : fname_(path) {
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
  case PF_GET_OPTIONS(PF_OPEN_ALWAYS):
    creation_disposition = OPEN_ALWAYS;
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
    // TODO(#2001): set up a security descriptor based off the perms
  }

  handle_ = ::CreateFileA(path.c_str(),
                          access_mask,
                          FILE_SHARE_READ,
                          security_attrs.get(),
                          creation_disposition,
                          flags_and_attrs,
                          nullptr);

  /// Normally, append is done via the FILE_APPEND_DATA access mask. However,
  /// because we are blanket using GENERIC_WRITE, this will not work. To
  /// compensate, we can emulate the behavior by seeking to the file end
  if (handle_ != INVALID_HANDLE_VALUE && (mode & PF_APPEND) == PF_APPEND) {
    seek(0, PF_SEEK_END);
  }
}

PlatformFile::~PlatformFile() {
  if (handle_ != kInvalidHandle && handle_ != nullptr) {
    // Only cancel IO if we are a non-blocking HANDLE
    if (is_nonblock_) {
      ::CancelIo(handle_);
    }

    ::CloseHandle(handle_);
    handle_ = kInvalidHandle;
  }
}

bool PlatformFile::isSpecialFile() const {
  return (::GetFileType(handle_) != FILE_TYPE_DISK);
}

static Status isUserCurrentUser(PSID user) {
  BOOL ret = FALSE;
  HANDLE token = INVALID_HANDLE_VALUE;

  if (!::IsValidSid(user)) {
    return Status(-1, "Invalid SID");
  }

  if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_READ, &token)) {
    return Status(-1, "OpenProcessToken failed");
  }

  DWORD size = 0;
  PTOKEN_USER ptu = nullptr;

  ret = ::GetTokenInformation(token, TokenUser, (LPVOID)ptu, 0, &size);
  if (ret || (!ret && ::GetLastError() != ERROR_INSUFFICIENT_BUFFER)) {
    ::CloseHandle(token);

    return Status(-1, "GetTokenInformation failed (1)");
  }

  std::vector<char> buffer(size);
  ptu = (PTOKEN_USER)buffer.data();

  /// Obtain the user SID behind the token handle
  ret = ::GetTokenInformation(token, TokenUser, (LPVOID)ptu, size, &size);
  ::CloseHandle(token);

  if (!ret) {
    return Status(-1, "GetTokenInformation failed (2)");
  }

  /// Determine if the current user SID matches that of the specified user
  if (::EqualSid(user, ptu->User.Sid)) {
    return Status(0, "OK");
  }

  return Status(1, "User not current user");
}

Status PlatformFile::isOwnerRoot() const {
  if (!isValid()) {
    return Status(-1, "Invalid handle_");
  }

  PSID owner = nullptr;
  PSECURITY_DESCRIPTOR sd = nullptr;

  if (::GetSecurityInfo(handle_,
                        SE_FILE_OBJECT,
                        OWNER_SECURITY_INFORMATION,
                        &owner,
                        nullptr,
                        nullptr,
                        nullptr,
                        &sd) != ERROR_SUCCESS) {
    return Status(-1, "GetSecurityInfo failed");
  }

  SecurityDescriptor sd_wrapper(sd);

  DWORD admins_buf_size = SECURITY_MAX_SID_SIZE;
  std::vector<char> admins_buf;
  admins_buf.assign(admins_buf_size, '\0');

  PSID admins_sid = (PSID)admins_buf.data();

  if (!::CreateWellKnownSid(
          WinBuiltinAdministratorsSid, nullptr, admins_sid, &admins_buf_size)) {
    return Status(-1, "CreateWellKnownSid failed");
  }

  if (::EqualSid(owner, admins_sid)) {
    return Status(0, "OK");
  }

  return Status(1, "Owner is not Administrators group");
}

Status PlatformFile::isOwnerCurrentUser() const {
  if (!isValid()) {
    return Status(-1, "Invalid handle_");
  }

  PSID owner = nullptr;
  PSECURITY_DESCRIPTOR sd = nullptr;

  if (::GetSecurityInfo(handle_,
                        SE_FILE_OBJECT,
                        OWNER_SECURITY_INFORMATION,
                        &owner,
                        nullptr,
                        nullptr,
                        nullptr,
                        &sd) != ERROR_SUCCESS) {
    return Status(-1, "GetSecurityInfo failed");
  }

  SecurityDescriptor sd_wrapper(sd);

  return isUserCurrentUser(owner);
}

Status PlatformFile::isExecutable() const {
  return hasAccess(handle_, X_OK);
}

static Status isWriteDenied(PACL acl) {
  if (acl == nullptr) {
    return Status(-1, "Invalid ACL pointer");
  }

  DWORD sid_buffer_size = SECURITY_MAX_SID_SIZE;

  std::vector<char> sid_buffer;
  sid_buffer.assign(sid_buffer_size, '\0');

  PSID world = (PSID)sid_buffer.data();

  if (!::CreateWellKnownSid(WinWorldSid, nullptr, world, &sid_buffer_size)) {
    return Status(-1, "CreateWellKnownSid failed");
  }

  PACE_HEADER entry = nullptr;
  for (DWORD i = 0; i < acl->AceCount; i++) {
    if (!::GetAce(acl, i, (LPVOID*)&entry)) {
      return Status(-1, "GetAce failed");
    }

    /*
     * Check to see if the deny ACE is for Everyone while making sure that there
     * must be no allow ACE that allow for writes before the denies
     */
    if (entry->AceType == ACCESS_DENIED_ACE_TYPE) {
      PACCESS_DENIED_ACE denied_ace = (PACCESS_DENIED_ACE)entry;

      if (::EqualSid(&denied_ace->SidStart, world) &&
          (denied_ace->Mask & CHMOD_WRITE) == CHMOD_WRITE) {
        return Status(0, "OK");
      }
    } else if (entry->AceType == ACCESS_ALLOWED_ACE_TYPE) {
      // This covers the case where the DACL has been modified by platformChmod
      PACCESS_ALLOWED_ACE allowed_ace = (PACCESS_ALLOWED_ACE)entry;

      // Check to see if ANY of CHMOD_WRITE rights are set
      if ((allowed_ace->Mask & CHMOD_WRITE) != 0) {
        // Fail, since we discovered an access allowed ACE that enables write
        break;
      }
    }
  }

  return Status(1, "No deny ACE for write");
}

Status PlatformFile::hasSafePermissions() const {
  PACL file_dacl = nullptr;
  PSECURITY_DESCRIPTOR file_sd = nullptr;

  if (::GetSecurityInfo(handle_,
                        SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION,
                        nullptr,
                        nullptr,
                        &file_dacl,
                        nullptr,
                        &file_sd) != ERROR_SUCCESS) {
    return Status(-1, "GetSecurityInfo failed");
  }

  SecurityDescriptor file_sd_wrapper(file_sd);

  std::vector<char> path_buf;
  path_buf.assign(MAX_PATH + 1, '\0');

  // Derive the parent directory and insure it also has safe permissions
  if (::GetFinalPathNameByHandleA(
          handle_, path_buf.data(), MAX_PATH, FILE_NAME_NORMALIZED) == 0) {
    return Status(-1, "GetFinalPathNameByHandleA failed");
  }

  if (!::PathRemoveFileSpecA(path_buf.data())) {
    return Status(-1, "PathRemoveFileSpec");
  }

  PACL dir_dacl = nullptr;
  PSECURITY_DESCRIPTOR dir_sd = nullptr;

  if (::GetNamedSecurityInfoA(path_buf.data(),
                              SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION,
                              nullptr,
                              nullptr,
                              &dir_dacl,
                              nullptr,
                              &dir_sd) != ERROR_SUCCESS) {
    return Status(-1, "GetNamedSecurityInfoA failed for dir");
  }

  SecurityDescriptor dir_sd_wrapper(dir_sd);

  if (isWriteDenied(file_dacl).ok() && isWriteDenied(dir_dacl).ok()) {
    return Status(0, "OK");
  }

  return Status(1, "Not safe for loading");
}

bool PlatformFile::getFileTimes(PlatformTime& times) {
  if (!isValid()) {
    return false;
  }

  return (::GetFileTime(handle_, nullptr, &times.times[0], &times.times[1]) !=
          FALSE);
}

bool PlatformFile::setFileTimes(const PlatformTime& times) {
  if (!isValid()) {
    return false;
  }

  return (::SetFileTime(handle_, nullptr, &times.times[0], &times.times[1]) !=
          FALSE);
}

ssize_t PlatformFile::getOverlappedResultForRead(void* buf,
                                                 size_t requested_size) {
  ssize_t nret = 0;
  DWORD bytes_read = 0;
  DWORD last_error = 0;

  if (::GetOverlappedResult(handle_, &last_read_.overlapped_, &bytes_read, 0)) {
    // Read operation has finished

    // NOTE: We do NOT support situations where the second read operation uses a
    // SMALLER buffer than the initial async request. This will cause the
    // smaller amount to be copied and truncate DATA!
    DWORD size = static_cast<DWORD>(min(requested_size, bytes_read));
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

ssize_t PlatformFile::read(void* buf, size_t nbyte) {
  if (!isValid()) {
    return -1;
  }

  ssize_t nret = -1;
  unsigned long bytes_read = 0;
  unsigned long last_error = 0;

  has_pending_io_ = false;

  if (is_nonblock_) {
    if (last_read_.is_active_) {
      nret = getOverlappedResultForRead(buf, nbyte);
    } else {
      last_read_.overlapped_.Offset = cursor_;
      last_read_.buffer_.reset(new char[nbyte]);
      auto ret = ::ReadFile(handle_,
                            last_read_.buffer_.get(),
                            static_cast<unsigned long>(nbyte),
                            &bytes_read,
                            &last_read_.overlapped_);
      if (ret != 0) {
        memcpy_s(buf, nbyte, last_read_.buffer_.get(), bytes_read);
        nret = bytes_read;
        cursor_ += bytes_read;
      } else {
        last_error = ::GetLastError();
        if (last_error == ERROR_IO_PENDING || last_error == ERROR_MORE_DATA) {
          nret = getOverlappedResultForRead(buf, nbyte);
        }
      }
    }
  } else {
    auto ret = ::ReadFile(
        handle_, buf, static_cast<unsigned long>(nbyte), &bytes_read, nullptr);
    if (ret != 0) {
      nret = bytes_read;
    }
  }
  return nret;
}

ssize_t PlatformFile::write(const void* buf, size_t nbyte) {
  if (!isValid()) {
    return -1;
  }

  ssize_t nret = 0;
  unsigned long bytes_written = 0;
  unsigned long last_error = 0;

  has_pending_io_ = false;

  if (is_nonblock_) {
    AsyncEvent write_event;
    auto ret = ::WriteFile(handle_,
                           buf,
                           static_cast<unsigned long>(nbyte),
                           &bytes_written,
                           &write_event.overlapped_);
    if (ret == 0) {
      last_error = ::GetLastError();
      if (last_error == ERROR_IO_PENDING) {
        ret = ::GetOverlappedResult(
            handle_, &write_event.overlapped_, &bytes_written, 0);
        if (ret == 0) {
          last_error = ::GetLastError();
          if (last_error == ERROR_IO_INCOMPLETE) {
            has_pending_io_ = true;
            // If the write operation has not succeeded, cancel it
            ::CancelIo(handle_);
            nret = -1;
          } else {
            // Error of unknown origin
            TLOG << "Write to " << fname_ << " failed with error ("
                 << GetLastError() << ")";
            nret = -1;
          }
        } else {
          // Write operation succeeded
          nret = bytes_written;
        }
      } else {
        TLOG << "Write to " << fname_ << " failed with error ("
             << GetLastError() << ")";
        nret = -1;
      }
    } else {
      nret = bytes_written;
    }
  } else {
    if (!::WriteFile(handle_,
                     buf,
                     static_cast<unsigned long>(nbyte),
                     &bytes_written,
                     nullptr)) {
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
  PSECURITY_DESCRIPTOR sd = nullptr;

  ret = ::GetNamedSecurityInfoA(path.c_str(),
                                SE_FILE_OBJECT,
                                OWNER_SECURITY_INFORMATION |
                                    GROUP_SECURITY_INFORMATION |
                                    DACL_SECURITY_INFORMATION,
                                &owner,
                                &group,
                                &dacl,
                                nullptr,
                                &sd);

  if (ret != ERROR_SUCCESS) {
    return false;
  }

  SecurityDescriptor sd_wrapper(sd);

  if (owner == nullptr || group == nullptr || dacl == nullptr) {
    return false;
  }

  DWORD sid_size = SECURITY_MAX_SID_SIZE;
  std::vector<char> world_buf(sid_size);
  PSID world = (PSID)world_buf.data();

  if (!::CreateWellKnownSid(WinWorldSid, nullptr, world, &sid_size)) {
    return false;
  }

  PACL acl = nullptr;
  AclObject acl_buffer = modifyAcl(dacl,
                                   owner,
                                   (perms & S_IRUSR) == S_IRUSR,
                                   (perms & S_IWUSR) == S_IWUSR,
                                   (perms & S_IXUSR) == S_IXUSR,
                                   true);
  acl = reinterpret_cast<PACL>(acl_buffer.get());

  if (acl == nullptr) {
    return false;
  }

  acl_buffer = modifyAcl(acl,
                         group,
                         (perms & S_IRGRP) == S_IRGRP,
                         (perms & S_IWGRP) == S_IWGRP,
                         (perms & S_IXGRP) == S_IXGRP);
  acl = reinterpret_cast<PACL>(acl_buffer.get());

  if (acl == nullptr) {
    return false;
  }

  acl_buffer = modifyAcl(acl,
                         world,
                         (perms & S_IROTH) == S_IROTH,
                         (perms & S_IWOTH) == S_IWOTH,
                         (perms & S_IXOTH) == S_IXOTH);
  acl = reinterpret_cast<PACL>(acl_buffer.get());

  if (acl == nullptr) {
    return false;
  }

  // SetNamedSecurityInfoA takes a mutable string for the path parameter
  std::vector<char> mutable_path(path.begin(), path.end());
  mutable_path.push_back('\0');

  if (::SetNamedSecurityInfoA(mutable_path.data(),
                              SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION,
                              nullptr,
                              nullptr,
                              acl,
                              nullptr) != ERROR_SUCCESS) {
    return false;
  }

  return true;
}

std::vector<std::string> platformGlob(const std::string& find_path) {
  fs::path full_path(find_path);

  /*
   * This is a naive implementation of GLOB_TILDE. If the first two characters
   * in the path are '~/' or '~\', we replace it with the value of the
   * USERPROFILE environment variable.
   */
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
    /*
     * The provided glob pattern contains more than one directory to traverse.
     * We enumerate each component in the path to generate a list of all
     * possible directories that we need to perform our glob pattern match.
     */
    for (auto& component : full_path.parent_path()) {
      std::vector<fs::path> tmp_valid_paths;

      /*
       * This will enumerate the old set of valid paths and update it by looking
       * for directories matching the specified glob pattern.
       */
      for (auto const& valid_path : valid_paths) {
        if (hasGlobBraces(component.string())) {
          /*
           * If the component contains braces, we convert the component into a
           * regex, enumerate through all the directories in the current
           * directory and only mark the ones fitting the regex pattern as
           * valid.
           */
          std::regex component_pattern(globToRegex(component.string()));
          WindowsFindFiles wf(valid_path / "*");
          for (auto const& file_path : wf.getDirectories()) {
            if (std::regex_match(file_path.filename().string(),
                                 component_pattern)) {
              tmp_valid_paths.push_back(file_path);
            }
          }
        } else if (std::regex_match(component.string(), pattern)) {
          /*
           * If the component contains wildcard characters such as * or ?, we
           * pass the pattern into the Windows FindFirstFileA function to get a
           * list of valid directories.
           */
          WindowsFindFiles wf(valid_path / component);
          for (auto const& result : wf.getDirectories()) {
            tmp_valid_paths.push_back(result);
          }
        } else {
          /*
           * Since there are no braces and other glob-like wildcards, we are
           * going to append the component to the previous valid path and append
           * the new path to the list
           */
          boost::system::error_code ec;
          if (fs::exists(valid_path / component, ec) &&
              ec.value() == errc::success) {
            fs::path tmp_vpath =
                component.string() != "." ? valid_path / component : valid_path;
            tmp_valid_paths.push_back(tmp_vpath);
          }
        }
      }
      valid_paths.swap(tmp_valid_paths);
    }
  }

  std::vector<std::string> results;

  /*
   * After generating all the valid directories, we enumerate the valid paths
   * and instead of getting back all the glob pattern matching directories, we
   * unrestrict it to get back files as well. We append the file names to the
   * valid paths are return the list.
   */
  for (auto const& valid_path : valid_paths) {
    if (hasGlobBraces(full_path.filename().string())) {
      std::regex component_pattern(globToRegex(full_path.filename().string()));
      WindowsFindFiles wf(valid_path / "*");
      for (auto& result : wf.get()) {
        if (std::regex_match(result.filename().string(), component_pattern)) {
          auto result_path = result.make_preferred().string();

          boost::system::error_code ec;
          if (fs::is_directory(result, ec) && ec.value() == errc::success) {
            result_path += "\\";
          }
          results.push_back(result_path);
        }
      }
    } else {
      fs::path glob_path = full_path.filename() == "."
                               ? valid_path
                               : valid_path / full_path.filename();

      WindowsFindFiles wf(glob_path);
      for (auto& result : wf.get()) {
        auto result_path = result.make_preferred().string();

        boost::system::error_code ec;
        if (fs::is_directory(result, ec) && ec.value() == errc::success) {
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
    return value;
  } else if (SUCCEEDED(::SHGetFolderPathA(
                 nullptr, CSIDL_PROFILE, nullptr, 0, profile.data()))) {
    return std::string(profile.data());
  } else {
    return boost::none;
  }
}

int platformAccess(const std::string& path, mode_t mode) {
  auto status = hasAccess(path, mode);
  if (status.ok()) {
    return 0;
  }

  // Error or invalid access right
  return -1;
}

static std::string normalizeDirPath(const fs::path& path) {
  std::regex pattern(".*[*?\"|<>].*");

  std::vector<char> full_path(MAX_PATH + 1);
  std::vector<char> final_path(MAX_PATH + 1);

  full_path.assign(MAX_PATH + 1, '\0');
  final_path.assign(MAX_PATH + 1, '\0');

  // Fail if illegal characters are detected in the path
  if (std::regex_match(path.string(), pattern)) {
    return std::string();
  }

  // Obtain the full path of the fs::path object
  DWORD nret = ::GetFullPathNameA(
      (LPCSTR)path.string().c_str(), MAX_PATH, full_path.data(), nullptr);
  if (nret == 0) {
    return std::string();
  }

  HANDLE handle = INVALID_HANDLE_VALUE;
  handle = ::CreateFileA(full_path.data(),
                         GENERIC_READ,
                         FILE_SHARE_READ,
                         nullptr,
                         OPEN_EXISTING,
                         FILE_FLAG_BACKUP_SEMANTICS,
                         nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return std::string();
  }

  // Resolve any symbolic links (somewhat rare on Windows)
  nret = ::GetFinalPathNameByHandleA(
      handle, final_path.data(), MAX_PATH, FILE_NAME_NORMALIZED);
  ::CloseHandle(handle);

  if (nret == 0) {
    return std::string();
  }

  // NTFS is case insensitive, to normalize, make everything uppercase
  ::CharUpperA(final_path.data());

  boost::system::error_code ec;
  std::string normalized_path(final_path.data(), nret);
  if ((fs::is_directory(normalized_path, ec) && ec.value() == errc::success) &&
      normalized_path[nret - 1] != '\\') {
    normalized_path += "\\";
  }
  return normalized_path;
}

static bool dirPathsAreEqual(const fs::path& dir1, const fs::path& dir2) {
  std::string normalized_path1 = normalizeDirPath(dir1);
  std::string normalized_path2 = normalizeDirPath(dir2);

  return (normalized_path1.size() > 0 && normalized_path2.size() > 0 &&
          normalized_path1 == normalized_path2);
}

Status platformIsTmpDir(const fs::path& dir) {
  boost::system::error_code ec;
  if (!dirPathsAreEqual(dir, fs::temp_directory_path(ec))) {
    return Status(1, "Not temp directory");
  }

  return Status(0, "OK");
}

Status platformIsFileAccessible(const fs::path& path) {
  boost::system::error_code ec;
  if (fs::is_regular_file(path, ec) && ec.value() == errc::success) {
    return Status(0, "OK");
  }
  return Status(1, "Not accessible file");
}

bool platformIsatty(FILE* f) {
  return 0 != _isatty(_fileno(f));
}

boost::optional<FILE*> platformFopen(const std::string& filename,
                                     const std::string& mode) {
  FILE* fp = nullptr;

  auto status = ::fopen_s(&fp, filename.c_str(), mode.c_str());
  if (status != 0) {
    return boost::none;
  }

  if (fp == nullptr) {
    return boost::none;
  }

  return fp;
}

/**
 * @brief The windows implementation introduces a 500ms max wait.
 *
 * We cannot use existing methods to determine the lifespan of the
 * extensions/extensions manager socket. On Windows, the Thrift install is
 * brittle and does not like a quick connect and disconnect. To compensate, we
 * use WaitNamedPipe to determine the existence of a named pipe. If the named
 * pipe does not exist, WaitNamedPipe should error with ERROR_BAD_PATHNAME.
 */
Status socketExists(const fs::path& path, bool remove_socket) {
  DWORD timeout = (remove_socket) ? 0 : 500;
  if (::WaitNamedPipeA(path.string().c_str(), timeout) == 0) {
    DWORD error = ::GetLastError();
    if (error == ERROR_BAD_PATHNAME) {
      return Status(1, "Named pipe path is invalid");
    } else if (error == ERROR_FILE_NOT_FOUND) {
      if (remove_socket) {
        return Status(0);
      }

      return Status(1, "Named pipe does not exist");
    }
  }
  return Status(0, "OK");
}

LONGLONG filetimeToUnixtime(const FILETIME& ft) {
  LARGE_INTEGER date, adjust;
  date.HighPart = ft.dwHighDateTime;
  date.LowPart = ft.dwLowDateTime;
  adjust.QuadPart = 11644473600000 * 10000;
  date.QuadPart -= adjust.QuadPart;
  return date.QuadPart / 10000000;
}

fs::path getSystemRoot() {
  std::vector<char> winDirectory(MAX_PATH + 1);
  ZeroMemory(winDirectory.data(), MAX_PATH + 1);
  GetWindowsDirectory(winDirectory.data(), MAX_PATH);
  return fs::path(std::string(winDirectory.data()));
}
}
