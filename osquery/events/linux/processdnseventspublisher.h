/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <ebpfpub/iperfeventreader.h>
#include <osquery/events.h>

#include <vector>

namespace osquery {
struct ProcessDNSEventsSubscriptionContext final : public SubscriptionContext {
 private:
  friend class ProcessDNSEventsPublisher;
};

struct ProcessDNSEvent final {
  std::uint64_t timestamp;

  uid_t user_id{};
  gid_t group_id{};

  pid_t process_id{};
  pid_t thread_id{};

  int exit_code{};

  std::string node;
  std::string service;
};

using ProcessDNSEventList = std::vector<ProcessDNSEvent>;

struct DNSEventContext final : public EventContext {
  ProcessDNSEventList event_list;
};

using DNSEventContextRef = std::shared_ptr<DNSEventContext>;

class ProcessDNSEventsPublisher final
    : public EventPublisher<ProcessDNSEventsSubscriptionContext,
                            DNSEventContext> {
  DECLARE_PUBLISHER("processdnseventspublisher");

  tob::ebpfpub::IBufferStorage::Ref buffer_storage;
  tob::ebpf::PerfEventArray::Ref perf_event_array;
  tob::ebpfpub::IPerfEventReader::Ref perf_event_reader;

 public:
  Status setUp() override;
  void configure() override;
  void tearDown() override;
  Status run() override;
  virtual ~ProcessDNSEventsPublisher() override;
};
} // namespace osquery
