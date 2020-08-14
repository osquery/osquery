/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/utils/expected/expected.h>

#include <linux/bpf.h>
#include <linux/version.h>

#if defined(LINUX_VERSION_CODE) && LINUX_VERSION_CODE < 263946
#define BPF_PROG_TYPE_TRACEPOINT (bpf_prog_type)(BPF_PROG_TYPE_SCHED_ACT + 1)
#endif

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
