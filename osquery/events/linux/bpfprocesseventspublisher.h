/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/events.h>

#include <ebpfpub/ifunctiontracer.h>
#include <ebpfpub/iperfeventreader.h>

#include <vector>

namespace osquery {
struct BPFProcessEventsSC final : public SubscriptionContext {
 private:
  friend class BPFProcessEventsPublisher;
};

struct BPFProcessEventsEC final : public EventContext {
  struct Event final {
    std::uint64_t timestamp{0};
    pid_t thread_id{0};
    pid_t process_id{0};
    uid_t user_id{0};
    gid_t group_id{0};
    std::int64_t cgroup_id{0};
    std::int64_t exit_code{0};
    bool probe_error{false};

    std::string syscall_name;

    std::string binary_path;
    std::vector<std::string> argument_list;
  };

  using EventList = std::vector<Event>;

  EventList event_list;
};

class BPFProcessEventsPublisher final
    : public EventPublisher<BPFProcessEventsSC, BPFProcessEventsEC> {
 public:
  BPFProcessEventsPublisher();
  virtual ~BPFProcessEventsPublisher() override;

  virtual Status setUp() override;
  virtual void configure() override;
  virtual Status run() override;
  virtual void tearDown() override;

  void eventCallback(
      const tob::ebpfpub::IFunctionTracer::EventList& bpf_event_list,
      const tob::ebpfpub::IPerfEventReader::ErrorCounters& error_counters);

 private:
  DECLARE_PUBLISHER("BPFProcessEventsPublisher");

  struct PrivateData;
  std::unique_ptr<PrivateData> d;
};
} // namespace osquery
