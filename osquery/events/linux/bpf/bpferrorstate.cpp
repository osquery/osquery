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

void reportAndClearBpfErrorState(BPFErrorState& bpf_error_state) {
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
