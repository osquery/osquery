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

#include <osquery/utils/expected/expected.h>
#include <osquery/utils/system/linux/tracing/types.h>

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

  static Expected<EbpfTracepoint, Error> load(
      tracing::SystemEventId system_event_id, int ebpf_prog_fd);

 private:
  explicit EbpfTracepoint() = default;

  ExpectedSuccess<Error> unload();

  void forceUnload();

 private:
  int fd_ = -1;
};

} // namespace events
} // namespace osquery
