/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/events/eventpublisher.h>
#include <osquery/events/eventsubscriber.h>

#include <memory>
#include <vector>

// Forward declarations for BPF skeleton types
struct bpf_process_events_bpf;
struct ring_buffer;

namespace osquery {

struct BPFProcessEvent {
  uint64_t timestamp;
  uint64_t pid;
  uint64_t tid;
  uint64_t ppid;
  uint64_t uid;
  uint64_t gid;
  uint32_t cgroup_id;
  int64_t exit_code;
  uint64_t duration;
  uint8_t probe_error;

  std::string comm;
  std::string path;
  std::string cwd;
  std::string args;
};

using BPFProcessEventList = std::vector<BPFProcessEvent>;

struct BPFProcessEventSubscriptionContext : public SubscriptionContext {
  // No specific subscription context needed for now
};

struct BPFProcessEventContext : public EventContext {
  BPFProcessEventList event_list;
};

using BPFProcessEventContextRef = std::shared_ptr<BPFProcessEventContext>;
using BPFProcessEventSubscriptionContextRef =
    std::shared_ptr<BPFProcessEventSubscriptionContext>;

class BPFProcessEventPublisher
    : public EventPublisher<BPFProcessEventSubscriptionContext,
                            BPFProcessEventContext> {
  DECLARE_PUBLISHER("bpf_process_events");

 public:
  Status setUp() override;
  void configure() override;
  void tearDown() override;

  Status run() override;

 private:
  // BPF program skeleton
  std::unique_ptr<struct ::bpf_process_events_bpf,
                  void (*)(struct ::bpf_process_events_bpf*)>
      skel_{nullptr, nullptr};

  // Ring buffer for receiving events
  std::unique_ptr<struct ::ring_buffer, void (*)(struct ::ring_buffer*)> rb_{
      nullptr, nullptr};

  // Process events from ring buffer
  void processEvents();

  // Ring buffer callback (static for C API)
  static int handleEvent(void* ctx, void* data, size_t data_sz);

  // Thread-local storage for event batching
  BPFProcessEventList pending_events_;
};

} // namespace osquery
