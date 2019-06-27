/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
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
