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
#include <string>
#include <vector>
#include <sstream>

#include <boost/optional.hpp>
#include <boost/filesystem.hpp>

#include <io.h>

#include "osquery/filesystem/fileops.h"
#include "osquery/core/process.h"

namespace fs = boost::filesystem;

namespace osquery {

#define CHMOD_READ    SYNCHRONIZE | READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_READ_EA | FILE_READ_DATA
#define CHMOD_WRITE   FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE
#define CHMOD_EXECUTE FILE_EXECUTE 

using SidObject = std::unique_ptr<unsigned char>;
using AclObject = std::unique_ptr<unsigned char>;

class WindowsFindFiles {
public:
  explicit WindowsFindFiles(fs::path path) : path_(path) {
    handle_ = ::FindFirstFileA(path.make_preferred().string().c_str(), &fd_);
  }

  ~WindowsFindFiles() {
    if (handle_ != INVALID_HANDLE_VALUE) {
      FindClose(handle_);
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
    for (auto const &result : get()) {
      if (fs::is_directory(result)) {
        results.push_back(result);
      }
    }
    return results;
  }

private:
  HANDLE handle_ = INVALID_HANDLE_VALUE;
  WIN32_FIND_DATAA fd_ = {0};

  fs::path path_;
};

static bool hasGlobBraces(const std::string &glob) {
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

/// Inspired by glob-to-regexp node package
static std::string globToRegex(const std::string &glob) {
  bool in_group = false;
  std::string regex("");

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

  return "^" + regex + "$";
}

static DWORD getNewAclSize(PACL dacl, PSID sid, ACL_SIZE_INFORMATION& info, bool needs_allowed, bool needs_denied) {
  DWORD acl_size = info.AclBytesInUse;
  if (needs_allowed) {
    acl_size += sizeof(ACCESS_ALLOWED_ACE) + ::GetLengthSid(sid) - sizeof(DWORD);
  }

  if (needs_denied) {
    acl_size += sizeof(ACCESS_DENIED_ACE) + ::GetLengthSid(sid) - sizeof(DWORD);
  }

  PACE_HEADER entry = nullptr;
  for (DWORD i = 0; i < info.AceCount; i++) {
    if (!::GetAce(dacl, i, (LPVOID *)&entry)) {
      return 0;
    }

    if (entry->AceType == ACCESS_ALLOWED_ACE_TYPE &&
      ::EqualSid(sid, &((ACCESS_ALLOWED_ACE *)entry)->SidStart)) {
      acl_size -= sizeof(ACCESS_ALLOWED_ACE) + ::GetLengthSid(sid) - sizeof(DWORD);
    }

    if (entry->AceType == ACCESS_DENIED_ACE_TYPE &&
      ::EqualSid(sid, &((ACCESS_DENIED_ACE *)entry)->SidStart)) {
      acl_size -= sizeof(ACCESS_DENIED_ACE) + ::GetLengthSid(sid) - sizeof(DWORD);
    }

    if (entry->AceFlags & INHERITED_ACE) {
      break;
    }
  }

  return acl_size;
}

static AclObject modifyAcl(PACL acl, PSID target, bool allow_read, bool allow_write, bool allow_exec) {
  if (acl == nullptr && target == nullptr) {
    return std::move(AclObject());
  }

  DWORD allow_mask = 0;
  DWORD deny_mask = 0;

  ACL_SIZE_INFORMATION info = { 0 };
  info.AclBytesInUse = sizeof(ACL);

  if (!::GetAclInformation(acl, &info, sizeof(info), AclSizeInformation)) {
    return std::move(AclObject());
  }

  if (allow_read) {
    allow_mask = CHMOD_READ;
  }
  else {
    deny_mask = CHMOD_READ;
  }

  if (allow_write) {
    allow_mask |= CHMOD_WRITE;
  }
  else {
    deny_mask |= CHMOD_WRITE;
  }

  if (allow_exec) {
    allow_mask |= CHMOD_EXECUTE;
  }
  else {
    deny_mask |= CHMOD_EXECUTE;
  }

  DWORD new_acl_size = 0;
  if (allow_read && allow_write && allow_exec) {
    new_acl_size = getNewAclSize(acl, target, info, true, false);
  }
  else if (!allow_read && !allow_write && !allow_exec) {
    new_acl_size = getNewAclSize(acl, target, info, false, true);
  }
  else {
    new_acl_size = getNewAclSize(acl, target, info, true, true);
  }

  AclObject new_acl_buffer(new unsigned char[new_acl_size]);
  PACL new_acl = reinterpret_cast<PACL>(new_acl_buffer.get());

  if (!::InitializeAcl(new_acl, new_acl_size, ACL_REVISION)) {
    return std::move(AclObject());
  }

  DWORD i = 0;
  PACE_HEADER entry = nullptr;
  for (i = 0; i < info.AceCount; i++) {
    if (!::GetAce(acl, i, (LPVOID *)&entry)) {
      return std::move(AclObject());
    }

    if (entry->AceFlags & INHERITED_ACE) {
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

bool platformChmod(const std::string& path, int perms) {
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
  SidObject world_buf(new unsigned char[sid_size]);
  PSID world = world_buf.get();

  if (!::CreateWellKnownSid(WinWorldSid, nullptr, world, &sid_size)) {
    return false;
  }

  PACL acl = nullptr;
  AclObject acl_buffer = modifyAcl(
    dacl, owner, static_cast<bool>(perms & 0x0100),
    static_cast<bool>(perms & 0x0080), static_cast<bool>(perms & 0x0040));
  acl = reinterpret_cast<PACL>(acl_buffer.get());
  if (acl == nullptr) {
    return false;
  }

  acl_buffer = modifyAcl(acl, group, static_cast<bool>(perms & 0x0020),
    static_cast<bool>(perms & 0x0010),
    static_cast<bool>(perms & 0x0008));
  acl = reinterpret_cast<PACL>(acl_buffer.get());
  if (acl == nullptr) {
    return false;
  }

  acl_buffer = modifyAcl(acl, world, static_cast<bool>(perms & 0x0004),
    static_cast<bool>(perms & 0x0002),
    static_cast<bool>(perms & 0x0001));
  acl = reinterpret_cast<PACL>(acl_buffer.get());
  if (acl == nullptr) {
    return false;
  }

  // SetNamedSecurityInfoA takes a mutable string for the path parameter
  std::vector<char> mutable_path(path.begin(), path.end());
  mutable_path.push_back('\0');

  if (!::SetNamedSecurityInfoA(&mutable_path[0], SE_FILE_OBJECT,
    DACL_SECURITY_INFORMATION, NULL, NULL, acl,
    NULL)) {
    return false;
  }
  return true;
}

std::vector<std::string> platformGlob(std::string find_path) {
  fs::path full_path(find_path);

  std::vector<fs::path> valid_paths;
  std::regex pattern(".*[*\?].*");

  /// TODO(#2001): We need to handle GLOB_TILDE and GLOB_MARK

  valid_paths.push_back(fs::path(""));
  if (full_path.has_parent_path()) {
    for (auto& component : full_path.parent_path()) {
      std::vector<fs::path> tmp_valid_paths;
      for (auto const& valid_path : valid_paths) {
        if (hasGlobBraces(component.string())) {
          std::regex component_pattern(globToRegex(component.string()));
          WindowsFindFiles wf(valid_path / "*");
          for (auto const& file_path : wf.getDirectories()) {
            if (std::regex_match(file_path.filename().string(), component_pattern)) {
              tmp_valid_paths.push_back(file_path);
            }
          }
        }
        else if (std::regex_match(component.string(), pattern)) {
          WindowsFindFiles wf(valid_path / component);
          tmp_valid_paths.swap(wf.getDirectories());
        }
        else {
          if (fs::exists(valid_path / component)) {
            tmp_valid_paths.push_back(valid_path / component);
          }
        }
      }
      valid_paths.swap(tmp_valid_paths);
    }
  }

  std::vector<std::string> results;
  for (auto const& valid_path : valid_paths) {
    if (hasGlobBraces(full_path.filename().string())) {
      std::regex component_pattern(globToRegex(full_path.filename().string()));
      WindowsFindFiles wf(valid_path / "*");
      for (auto& result : wf.get()) {
        if (std::regex_match(result.filename().string(), component_pattern)) {
          results.push_back(result.make_preferred().string());
        }
      }
    }
    else {
      WindowsFindFiles wf(valid_path / full_path.filename());
      for (auto& result : wf.get()) {
        results.push_back(result.make_preferred().string());
      }
    }
  }

  return results;
}

boost::optional<std::string> getHomeDirectory() {
  std::vector<char> profile(MAX_PATH);
  auto value = getEnvVar("USERPROFILE");
  if (value.is_initialized()) { // and writable...
    return *value;
  }
  else if (SUCCEEDED(::SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, &profile[0]))) {
    return std::string(&profile[0], ::strlen(&profile[0]));
  } else {
    return boost::none;
  }
}

int platformAccess(const std::string& path, int mode) {
  return _access(path.c_str(), mode);
}
}