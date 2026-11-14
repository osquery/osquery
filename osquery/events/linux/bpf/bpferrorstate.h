/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <ebpfpub/iperfeventreader.h>

#include <unordered_set>

namespace osquery {

/// A container for all the error counters the publisher works with
struct BPFErrorState final {
  /// perf_output related errors
  tob::ebpfpub::IPerfEventReader::ErrorCounters perf_error_counters{};

  /// Errors reported by the BPF probes we have loaded; this can be
  /// a failure to capture a string (example: open syscall) or a buffer
  /// (example: a sockaddr_in structure)
  std::size_t probe_error_counter{};

  /// A list of the tracers that have generated events we could not
  /// process correctly. This is likely caused by either lost events
  /// or probe errors (see above)
  std::unordered_set<std::uint64_t> errored_tracer_list;
};

/// Updates the error state structure with the given perf error counters
void updateBpfErrorState(
    BPFErrorState& bpf_error_state,
    const tob::ebpfpub::IPerfEventReader::ErrorCounters& perf_error_counters);

/// Logs the error state structure and then clears it
void reportAndClearBpfErrorState(BPFErrorState& bpf_error_state);

} // namespace osquery
