/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/events/linux/bpf/bpferrorstate.h>
#include <osquery/logger/logger.h>

namespace osquery {

namespace ebpfpub = tob::ebpfpub;

void updateBpfErrorState(
    BPFErrorState& bpf_error_state,
    const ebpfpub::IPerfEventReader::ErrorCounters& perf_error_counters) {
  bpf_error_state.perf_error_counters.invalid_event +=
      perf_error_counters.invalid_event;

  bpf_error_state.perf_error_counters.lost_events +=
      perf_error_counters.lost_events;

  bpf_error_state.perf_error_counters.invalid_probe_output +=
      perf_error_counters.invalid_probe_output;

  bpf_error_state.perf_error_counters.invalid_event_data +=
      perf_error_counters.invalid_event_data;
}

void reportAndClearBpfErrorState(BPFErrorState& bpf_error_state) {
  if (bpf_error_state.perf_error_counters.invalid_probe_output != 0U) {
    VLOG(1) << "Invalid BPF probe output error count: "
            << bpf_error_state.perf_error_counters.invalid_probe_output;
  }

  if (bpf_error_state.perf_error_counters.invalid_event != 0U) {
    VLOG(1) << "Invalid BPF probe event id count: "
            << bpf_error_state.perf_error_counters.invalid_event;
  }

  if (bpf_error_state.perf_error_counters.invalid_event_data != 0U) {
    VLOG(1) << "Invalid BPF event data count: "
            << bpf_error_state.perf_error_counters.invalid_event_data;
  }

  if (bpf_error_state.perf_error_counters.lost_events != 0U) {
    VLOG(1) << "Lost BPF event count: "
            << bpf_error_state.perf_error_counters.lost_events;
  }

  if (bpf_error_state.probe_error_counter != 0U) {
    VLOG(1) << "Buffers/strings that could not be captured by the probe: "
            << bpf_error_state.probe_error_counter;
  }

  if (!bpf_error_state.errored_tracer_list.empty()) {
    std::string tracer_list;

    for (auto tracer_it = bpf_error_state.errored_tracer_list.begin();
         tracer_it != bpf_error_state.errored_tracer_list.end();
         ++tracer_it) {
      if (tracer_it != bpf_error_state.errored_tracer_list.begin()) {
        tracer_list += ", ";
      }

      auto tracer_id = *tracer_it;
      tracer_list += std::to_string(tracer_id);
    }

    VLOG(1)
        << "Failed to process one or more events from the following tracers: " +
               tracer_list;
  }

  bpf_error_state = {};
}

} // namespace osquery
