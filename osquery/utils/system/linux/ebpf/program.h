/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/utils/expected/expected.h>

#include <linux/bpf.h>

namespace osquery {
namespace ebpf {

class Program final {
 public:
  Program(Program&& other);
  Program& operator=(Program&& other);

  Program(Program const&) = delete;
  Program& operator=(Program const&) = delete;

  ~Program();

  enum class Error {
    Unknown = 1,
    NotSupportedBySystem = 2,
  };

  static Expected<Program, Program::Error> load(
      std::vector<struct bpf_insn> prog,
      enum bpf_prog_type const program_type = BPF_PROG_TYPE_KPROBE,
      bool const debug = false);

  int fd() const;

 private:
  Program() = default;

 private:
  int fd_ = -1;
};

} // namespace ebpf
} // namespace osquery
