/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/events/linux/bpf/processcontextfactory.h>
#include <osquery/events/linux/bpf/uniquedir.h>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef O_PATH
#define O_PATH 010000000
#endif

namespace osquery {
namespace {
const std::size_t kMaxFileSize{1024 * 100};
const std::string kProcFsRoot{"/proc/"};
} // namespace

bool ProcessContextFactory::captureSingleProcess(
    ProcessContext& process_context, pid_t process_id) const {
  return captureSingleProcess(*fs.get(), process_context, process_id);
}

bool ProcessContextFactory::captureAllProcesses(
    ProcessContextMap& process_map) const {
  return captureAllProcesses(*fs.get(), process_map);
}

ProcessContextFactory::ProcessContextFactory(
    IFilesystem::Ref filesystem_interface) {
  fs = std::move(filesystem_interface);
}

bool ProcessContextFactory::captureSingleProcess(
    IFilesystem& fs, ProcessContext& process_context, pid_t process_id) {
  process_context = {};

  tob::utils::UniqueFd process_root;
  if (!fs.open(process_root,
               kProcFsRoot + std::to_string(process_id),
               O_DIRECTORY)) {
    return false;
  }

  tob::utils::UniqueFd process_fdmap;
  if (!fs.openAt(process_fdmap, process_root.get(), "fd", O_DIRECTORY)) {
    return false;
  }

  tob::utils::UniqueFd process_cmdline;
  if (!fs.openAt(process_cmdline, process_root.get(), "cmdline", O_RDONLY)) {
    return false;
  }

  tob::utils::UniqueFd process_stat;
  if (!fs.openAt(process_stat, process_root.get(), "stat", O_RDONLY)) {
    return false;
  }

  ProcessContext output;

  // clang-format off
  auto succeeded = fs.enumFiles(
    process_fdmap.get(),

    [&](const std::string &name, bool directory) {
      if (directory) {
        return;
      }

      char* null_terminator{nullptr};
      auto int_fd_value = std::strtoull(name.c_str(), &null_terminator, 10);
      if (null_terminator == nullptr || *null_terminator != '\0') {
        return;
      }

      std::string destination;
      if (!fs.readLinkAt(destination, process_fdmap.get(), name)) {
        return;
      }

      if (destination.find("anon_inode:[") == 0U) {
        return;
      }

      if (destination.find("mnt:[") == 0U) {
        return;
      }

      if (destination.find("net:[") == 0U) {
        return;
      }

      if (destination.find("pipe:[") == 0U) {
        return;
      }

      if (destination.find("socket:[") == 0U) {
        return;
      }

      ProcessContext::FileDescriptor fd_info;
      fd_info.path = std::move(destination);
      fd_info.close_on_exec = false;

      output.fd_map.insert({int_fd_value, fd_info});
    }
  );
  // clang-format on

  if (!succeeded) {
    return false;
  }

  succeeded = fs.readLinkAt(output.binary_path, process_root.get(), "exe");
  static_cast<void>(succeeded);

  succeeded = getArgvFromCmdlineFile(fs, output.argv, process_cmdline.get());
  static_cast<void>(succeeded);

  // If we failed to capture both fields, assume it's a special process
  // such as a kworker instance
  if (output.binary_path.empty() != output.argv.empty()) {
    return false;
  }

  if (!fs.readLinkAt(output.cwd, process_root.get(), "cwd")) {
    return false;
  }

  if (!getParentPidFromStatFile(
          fs, output.parent_process_id, process_stat.get())) {
    return false;
  }

  process_context = std::move(output);
  return true;
}

bool ProcessContextFactory::captureAllProcesses(
    IFilesystem& fs, ProcessContextMap& process_map) {
  process_map = {};

  tob::utils::UniqueFd process_root;
  if (!fs.open(process_root, kProcFsRoot, O_DIRECTORY)) {
    return false;
  }

  ProcessContextMap output;

  // clang-format off
  auto succeeded = fs.enumFiles(
    process_root.get(),

    [&](const std::string &name, bool directory) {
      if (!directory) {
        return;
      }

      char* null_terminator{nullptr};
      auto pid = static_cast<pid_t>(std::strtoull(name.c_str(), &null_terminator, 10));
      if (null_terminator == nullptr || *null_terminator != '\0') {
        return;
      }

      ProcessContext process_context = {};
      if (captureSingleProcess(fs, process_context, pid)) {
        output.insert({pid, std::move(process_context)});
      } else {
      }
    }
  );
  // clang-format on

  process_map = std::move(output);
  return succeeded;
}

bool ProcessContextFactory::getArgvFromCmdlineFile(
    IFilesystem& fs, std::vector<std::string>& argv, int fd) {
  std::vector<char> buffer;
  if (!fs.read(buffer, fd, kMaxFileSize)) {
    return false;
  }

  // TODO(alessandro): Parse!
  argv = {buffer.data()};
  return true;
}

bool ProcessContextFactory::getParentPidFromStatFile(IFilesystem& fs,
                                                     pid_t& parent_pid,
                                                     int fd) {
  parent_pid = -1;

  std::vector<char> buffer;
  if (!fs.read(buffer, fd, kMaxFileSize)) {
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

Status IProcessContextFactory::create(Ref& obj) {
  IFilesystem::Ref fs_interface;
  if (!IFilesystem::create(fs_interface)) {
    return Status::failure("Failed to create the filesystem interface");
  }

  try {
    obj.reset(new ProcessContextFactory(std::move(fs_interface)));
    return Status::success();

  } catch (const std::bad_alloc&) {
    return Status::failure("Memory allocation failure");

  } catch (const Status& s) {
    return s;
  }
}
} // namespace osquery
