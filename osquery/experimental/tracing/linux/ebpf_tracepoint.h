/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/utils/system/linux/ebpf/program.h>
#include <osquery/utils/system/linux/tracing/native_event.h>

#include <osquery/utils/expected/expected.h>

namespace osquery {
namespace events {

class EbpfTracepoint final {
 public:
  EbpfTracepoint(EbpfTracepoint&&);
  EbpfTracepoint& operator=(EbpfTracepoint&&);

  EbpfTracepoint(EbpfTracepoint const&) = delete;
  EbpfTracepoint& operator=(EbpfTracepoint const&) = delete;

  enum class Error {
    Unknown = 1,
    SystemError = 2,
  };

  ~EbpfTracepoint();

  static Expected<EbpfTracepoint, Error> load(tracing::NativeEvent system_event,
                                              ebpf::Program program);

 private:
  explicit EbpfTracepoint(tracing::NativeEvent system_event,
                          ebpf::Program program);

  ExpectedSuccess<Error> unload();

  void forceUnload();

 private:
  int fd_ = -1;

  tracing::NativeEvent system_event_;
  ebpf::Program program_;
};

} // namespace events
} // namespace osquery
