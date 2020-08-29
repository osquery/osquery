/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/linux/ebpf/program.h>
#include <osquery/utils/system/linux/ebpf/ebpf.h>

#include <boost/io/detail/quoted_manip.hpp>

#include <linux/version.h>

namespace osquery {
namespace ebpf {

Program::Program(Program&& other) : fd_(other.fd_) {
  other.fd_ = -1;
}

Program& Program::operator=(Program&& other) {
  std::swap(fd_, other.fd_);
  return *this;
}

Program::~Program() {
  if (fd_ > 0) {
    close(fd_);
    fd_ = -1;
  }
}

Expected<Program, Program::Error> Program::load(
    std::vector<struct bpf_insn> const prog,
    enum bpf_prog_type const program_type,
    bool const debug) {
  static char const* kLicense = "GPL";
  constexpr auto kLogBufSize = std::uint32_t{1 << 16};

  auto bpf_log_buf = std::array<char, kLogBufSize>{};
  union bpf_attr attr = {
      .prog_type = program_type,
      .insns = reinterpret_cast<__aligned_u64>(prog.data()),
      .insn_cnt = static_cast<std::uint32_t>(prog.size()),
      .license = reinterpret_cast<__aligned_u64>(kLicense),
      .log_buf = 0u,
      .log_size = 0u,
      .log_level = 0u,
      .kern_version = LINUX_VERSION_CODE,
  };
  if (debug) {
    bpf_log_buf.fill('\0');
    attr.log_buf = reinterpret_cast<std::uint64_t>(bpf_log_buf.data());
    attr.log_size = reinterpret_cast<std::uint32_t>(kLogBufSize);
    attr.log_level = 1;
  }
  auto instance = Program{};
  auto fd_exp = syscall(BPF_PROG_LOAD, &attr);
  if (fd_exp.isError()) {
    return createError(Program::Error::Unknown, fd_exp.takeError())
           << "eBPF program load failed, bpf log: "
           << boost::io::quoted(bpf_log_buf.data());
  }
  instance.fd_ = fd_exp.take();
  return Expected<Program, Program::Error>(std::move(instance));
}

int Program::fd() const {
  return fd_;
}

} // namespace ebpf
} // namespace osquery
