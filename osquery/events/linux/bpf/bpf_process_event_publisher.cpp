/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/events/linux/bpf/bpf_process_event_publisher.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>

// User-space shared event structure
#include "bpf_process_events.h"

// Helper for BPF enums
#include "../../../../libraries/cmake/source/libbpf/src/include/uapi/linux/bpf.h"

// Include generated BPF skeleton
#include <linux/bpf/bpf_process_events.skel.h>

// libbpf headers
#include <libbpf.h>

#include <chrono>
#include <cstring>

namespace osquery {

REGISTER(BPFProcessEventPublisher, "event_publisher", "bpf_process_events");

namespace {

// libbpf logging callback
int libbpfLogCallback(enum libbpf_print_level level,
                      const char* format,
                      va_list args) {
  static char buffer[1024 * 1024];
  vsnprintf(buffer, sizeof(buffer), format, args);

  if (level == LIBBPF_WARN || level == LIBBPF_INFO) {
    VLOG(1) << "libbpf: " << buffer;
  } else {
    LOG(WARNING) << "libbpf: " << buffer;
  }

  return 0;
}

} // namespace

Status BPFProcessEventPublisher::setUp() {
  // Set up libbpf logging
  libbpf_set_print(libbpfLogCallback);

  // Open BPF object
  auto* skel = bpf_process_events_bpf__open();
  if (!skel) {
    return Status::failure("Failed to open BPF skeleton");
  }

  // Store with custom deleter
  using SkelPtr = std::unique_ptr<struct ::bpf_process_events_bpf,
                                  void (*)(struct ::bpf_process_events_bpf*)>;
  skel_ = SkelPtr(skel, bpf_process_events_bpf__destroy);

  // Load BPF program into kernel
  int err = bpf_process_events_bpf__load(skel_.get());
  if (err) {
    return Status::failure("Failed to load BPF program: " +
                           std::string(strerror(-err)));
  }

  // Attach BPF programs to tracepoints
  err = bpf_process_events_bpf__attach(skel_.get());
  if (err) {
    return Status::failure("Failed to attach BPF program: " +
                           std::string(strerror(-err)));
  }

  LOG(INFO) << "BPF process events publisher initialized successfully";

  return Status::success();
}

void BPFProcessEventPublisher::configure() {
  // No specific configuration needed
}

void BPFProcessEventPublisher::tearDown() {
  // Clean up ring buffer
  rb_.reset();

  // Clean up BPF program
  skel_.reset();

  LOG(INFO) << "BPF process events publisher torn down";
}

Status BPFProcessEventPublisher::run() {
  if (!skel_) {
    return Status::failure("BPF skeleton not initialized");
  }

  // Set up ring buffer if not already done
  if (!rb_) {
    auto* rb = ring_buffer__new(bpf_map__fd(skel_->maps.events),
                                &BPFProcessEventPublisher::handleEvent,
                                this,
                                nullptr);

    if (!rb) {
      return Status::failure("Failed to create ring buffer");
    }

    rb_ =
        std::unique_ptr<struct ::ring_buffer, void (*)(struct ::ring_buffer*)>(
            rb, ring_buffer__free);
  }

  // Poll ring buffer with timeout
  int err = ring_buffer__poll(rb_.get(), 100 /* timeout_ms */);
  if (err < 0 && err != -EINTR) {
    LOG(WARNING) << "Ring buffer poll error: " << strerror(-err);
  }

  // Process any accumulated events
  processEvents();

  return Status::success();
}

int BPFProcessEventPublisher::handleEvent(void* ctx,
                                          void* data,
                                          size_t data_sz) {
  auto* publisher = static_cast<BPFProcessEventPublisher*>(ctx);

  if (data_sz < sizeof(struct process_event)) {
    LOG(WARNING) << "Invalid event size: " << data_sz;
    return 0;
  }

  auto* raw_event = static_cast<struct process_event*>(data);

  // Convert to our event structure
  BPFProcessEvent event;
  event.timestamp = raw_event->timestamp;
  event.pid = raw_event->pid;
  event.tid = raw_event->tid;
  event.ppid = raw_event->ppid;
  event.uid = raw_event->uid;
  event.gid = raw_event->gid;
  event.cgroup_id = raw_event->cgroup_id;
  event.exit_code = raw_event->exit_code;
  event.duration = raw_event->duration;
  event.probe_error = raw_event->probe_error;

  event.comm =
      std::string(raw_event->comm, strnlen(raw_event->comm, TASK_COMM_LEN));
  event.path =
      std::string(raw_event->path, strnlen(raw_event->path, MAX_PATH_LEN));
  event.cwd =
      std::string(raw_event->cwd, strnlen(raw_event->cwd, MAX_PATH_LEN));
  event.args =
      std::string(raw_event->args, strnlen(raw_event->args, MAX_ARGS_LEN));

  // Add to pending events
  publisher->pending_events_.push_back(std::move(event));

  return 0;
}

void BPFProcessEventPublisher::processEvents() {
  if (pending_events_.empty()) {
    return;
  }

  // Create event context with all pending events
  auto ec = createEventContext();
  ec->event_list = std::move(pending_events_);
  pending_events_.clear();

  // Fire event to subscribers
  fire(ec);
}

} // namespace osquery
