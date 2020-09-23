/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include "mockedprocesscontextfactory.h"

#include <osquery/events/linux/bpf/iprocesscontextfactory.h>

namespace osquery {
namespace {
ProcessContext createProcessContext(pid_t process_id) {
  ProcessContext process_context = {};

  if (process_id == 2) {
    process_context.parent_process_id = 1;

  } else if (process_id == 1000) {
    process_context.parent_process_id = 2;

  } else if (process_id == 1001) {
    process_context.parent_process_id = 1000;

  } else {
    throw std::logic_error(
        "Invalid process id specified in the process context factory");
  }

  process_context.binary_path = "/usr/bin/zsh";
  process_context.argv = {"zsh", "-H", "-i"};
  process_context.cwd = "/home/alessandro";

  // clang-format off
  process_context.fd_map = {
    { 0, { "/dev/pts/1", true } },
    { 1, { "/dev/pts/1", true } },
    { 2, { "/dev/pts/1", true } },
    { 11, { "/usr/share/zsh/functions/VCS_Info.zwc", false } },
    { 12, { "/usr/share/zsh/functions/Completion.zwc", false } },
    { 13, { "/usr/share/zsh/functions/VCS_Info/Backends.zwc", false } },
    { 14, { "/usr/share/zsh/functions/Completion/Base.zwc", false } },
    { 15, { "/usr/share/zsh/functions/Misc.zwc", false } }
  };
  // clang-format on

  return process_context;
}
} // namespace

std::size_t MockedProcessContextFactory::invocationCount() const {
  return invocation_count;
}

void MockedProcessContextFactory::failNextRequest() {
  fail_next_request = true;
}

bool MockedProcessContextFactory::captureSingleProcess(
    ProcessContext& process_context, pid_t process_id) const {
  if (fail_next_request) {
    fail_next_request = false;
    return false;
  }

  if (process_id == 1002) {
    return false;
  }

  ++invocation_count;

  process_context = createProcessContext(process_id);
  return true;
}

bool MockedProcessContextFactory::captureAllProcesses(
    ProcessContextMap& process_map) const {
  auto process_context = createProcessContext(2);
  process_map.insert({2, process_context});

  return true;
}
} // namespace osquery
