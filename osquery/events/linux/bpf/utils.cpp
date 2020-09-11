/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/events/linux/bpf/utils.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/tryto.h>

#include <tob/utils/uniquefd.h>

#include <dirent.h>
#include <fcntl.h>

namespace osquery {
namespace {
const std::string kProcfsRoot{"/proc/"};
const std::size_t kMaxFileSize{10240};

using UniqueDir = std::unique_ptr<DIR, decltype(&closedir)>;
} // namespace

bool readLinkAt(std::string& destination,
                int dirfd,
                const std::string& relative_path) {
  std::vector<char> buffer(4096);

  errno = 0;
  auto bytes_read = readlinkat(
      dirfd, relative_path.c_str(), buffer.data(), buffer.size() - 1U);

  if (bytes_read == -1) {
    return false;
  }

  destination.assign(buffer.data(), static_cast<std::size_t>(bytes_read));
  return true;
}

bool readFileAt(std::vector<char>& buffer,
                int dirfd,
                const std::string& relative_path) {
  buffer = {};

  tob::utils::UniqueFd file_handle;

  {
    auto fd = openat(dirfd, relative_path.c_str(), O_RDONLY);
    if (fd == -1) {
      return false;
    }

    file_handle.reset(fd);
  }

  std::vector<char> read_buffer(4096);
  while (buffer.size() < kMaxFileSize) {
    auto err = read(file_handle.get(), read_buffer.data(), read_buffer.size());
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

bool queryProcessArgv(std::vector<std::string>& argv, int procs_fd) {
  std::vector<char> buffer;
  if (!readFileAt(buffer, procs_fd, "cmdline")) {
    return false;
  }

  // TODO(alessandro): Parse!
  argv = {buffer.data()};
  return true;
}

bool queryProcessParentID(pid_t& parent_pid, int procs_fd) {
  std::vector<char> buffer;
  if (!readFileAt(buffer, procs_fd, "stat")) {
    return false;
  }

  auto parent_pid_r_it = std::find(buffer.rbegin(), buffer.rend(), ')');
  if (parent_pid_r_it == buffer.rend()) {
    return false;
  }

  auto parent_pid_it = std::next(parent_pid_r_it.base(), 4);
  if (parent_pid_it >= buffer.end()) {
    return false;
  }

  auto parent_pid_index = parent_pid_it - buffer.begin();
  auto parent_pid_ptr = &buffer[parent_pid_index];

  char* space_separator_ptr{nullptr};
  auto output_pid = std::strtoull(parent_pid_ptr, &space_separator_ptr, 10);

  // pid 0 is valid (example: kworker)
  if (space_separator_ptr == nullptr || *space_separator_ptr != ' ') {
    return false;
  }

  parent_pid = static_cast<pid_t>(output_pid);
  return true;
}

bool queryProcessFileDescriptorMap(ProcessContext::FileDescriptorMap& fd_map,
                                   int procs_fd) {
  fd_map = {};

  tob::utils::UniqueFd fd_directory;

  {
    auto fd = openat(procs_fd, "fd", O_DIRECTORY);
    if (fd == -1) {
      return false;
    }

    fd_directory.reset(fd);
  }

  UniqueDir directory(nullptr, closedir);

  {
    auto dir_obj = fdopendir(fd_directory.get());
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

    char* null_terminator{nullptr};
    auto fd = std::strtoull(string_fd, &null_terminator, 10);
    if (null_terminator == nullptr || *null_terminator != '\0') {
      return false;
    }

    std::string file_path;
    if (!readLinkAt(file_path, fd_directory.get(), entry->d_name)) {
      continue;
    }

    if (file_path.find("anon_inode:[") == 0U) {
      continue;
    }

    if (file_path.find("mnt:[") == 0U) {
      continue;
    }

    if (file_path.find("net:[") == 0U) {
      continue;
    }

    if (file_path.find("pipe:[") == 0U) {
      continue;
    }

    if (file_path.find("socket:[") == 0U) {
      continue;
    }

    ProcessContext::FileDescriptor fd_info;
    fd_info.path = std::move(file_path);
    fd_info.close_on_exec = false;

    fd_map.insert({fd, fd_info});
  }

  return true;
}

bool createProcessContext(ProcessContext& process_context, pid_t process_id) {
  tob::utils::UniqueFd process_root_fd;

  {
    auto process_root_path = kProcfsRoot + std::to_string(process_id);

    auto fd = open(process_root_path.c_str(), O_DIRECTORY);
    if (fd == -1) {
      return false;
    }

    process_root_fd.reset(fd);
  }

  // Attempt to parse the parent process id from the stat file
  if (!queryProcessParentID(process_context.parent_process_id,
                            process_root_fd.get())) {
    return false;
  }

  // If the parent process id is set to 0, then this may be a special
  // process (or a thread! like a kworker). We can expect cwd/exe/cmdline to
  // not work correctly, but we should still have access to an empty fd folder
  auto ignore_errors = process_context.parent_process_id == 0;

  // Get the current working directory
  if (!readLinkAt(process_context.cwd, process_root_fd.get(), "cwd") &&
      !ignore_errors) {
    return false;
  }

  // Get the binary path
  if (!readLinkAt(process_context.binary_path, process_root_fd.get(), "exe") &&
      !ignore_errors) {
    return false;
  }

  // Get the command line arguments
  if (!queryProcessArgv(process_context.argv, process_root_fd.get()) &&
      !ignore_errors) {
    return false;
  }

  // Enumerate the file descriptors for standard files
  return queryProcessFileDescriptorMap(process_context.fd_map,
                                       process_root_fd.get());
}

bool createProcessContextMap(ProcessContextMap& process_map) {
  process_map = {};

  std::vector<std::string> path_list;
  auto status = listDirectoriesInDirectory(kProcfsRoot, path_list, false);
  if (!status.ok()) {
    return false;
  }

  for (auto path : path_list) {
    // The listDirectoriesInDirectory() function appends a newline at the end
    path.resize(path.size() - 1U);
    auto dir_name = boost::filesystem::path(path).leaf().string();

    auto process_id_exp = tryTo<int>(dir_name);
    if (process_id_exp.isError()) {
      continue;
    }

    auto process_id = static_cast<pid_t>(process_id_exp.get());

    ProcessContext process_context = {};
    if (createProcessContext(process_context, process_id)) {
      process_map.insert({process_id, std::move(process_context)});
    } else {
      VLOG(1) << "Failed to create the process context from procfs for pid "
              << process_id;
    }
  }

  return !process_map.empty();
}
} // namespace osquery
