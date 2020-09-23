/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/events/linux/bpf/iprocesscontextfactory.h>

namespace osquery {
class ProcessContextFactory final : public IProcessContextFactory {
 public:
  virtual ~ProcessContextFactory() override = default;

  virtual bool captureSingleProcess(ProcessContext& process_context,
                                    pid_t process_id) const override;

  virtual bool captureAllProcesses(
      ProcessContextMap& process_map) const override;

 private:
  IFilesystem::Ref fs;

  ProcessContextFactory(IFilesystem::Ref fs);

 public:
  static bool captureSingleProcess(IFilesystem& fs,
                                   ProcessContext& process_context,
                                   pid_t process_id);

  static bool captureAllProcesses(IFilesystem& fs,
                                  ProcessContextMap& process_map);

  static bool getArgvFromCmdlineFile(IFilesystem& fs,
                                     std::vector<std::string>& argv,
                                     int fd);

  static bool getParentPidFromStatFile(IFilesystem& fs,
                                       pid_t& parent_pid,
                                       int fd);

  friend class IProcessContextFactory;
};
} // namespace osquery
