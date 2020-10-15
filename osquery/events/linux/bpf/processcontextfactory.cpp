/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/events/linux/bpf/processcontextfactory.h>
#include <osquery/events/linux/bpf/uniquedir.h>
#include <osquery/utils/conversions/tryto.h>

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

      auto int_fd_value_exp = tryTo<unsigned long long>(name, 10);
      if (int_fd_value_exp.isError()) {
        return;
      }

      auto int_fd_value = int_fd_value_exp.take();

      std::string destination;
      if (!fs.readLinkAt(destination, process_fdmap.get(),
                         name)) {
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
      fd_info.close_on_exec = false;

      ProcessContext::FileDescriptor::FileData file_data;
      file_data.path = std::move(destination);
      fd_info.data = std::move(file_data);

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

      auto pid_exp = tryTo<unsigned long long>(name, 10);
      if (pid_exp.isError()) {
        return;
      }

      auto pid = pid_exp.take();

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
  argv = {};

  std::vector<char> buffer;
  if (!fs.read(buffer, fd, kMaxFileSize)) {
    return false;
  }

  std::vector<std::string> output;
  std::size_t start = 0U;

  for (;;) {
    std::size_t end;
    for (end = start; end < buffer.size() && buffer.at(end) != 0; ++end)
      ;

    auto argument_size = end - start;
    if (argument_size == 0) {
      break;
    }

    auto argument = std::string(buffer.data() + start, argument_size);
    output.push_back(std::move(argument));

    start = end + 1;
    if (start >= buffer.size()) {
      break;
    }
  }

  argv = std::move(output);
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
