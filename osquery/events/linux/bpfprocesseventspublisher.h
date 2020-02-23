/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/events.h>

#include <ebpfpub/ifunctionserializer.h>

#include <vector>

namespace osquery {
struct BPFProcessEventsSC final : public SubscriptionContext {
 private:
  friend class BPFProcessEventsPublisher;
};

struct BPFProcessEventsEC final : public EventContext {
  struct SyscallEvent final {
    std::string syscall_name;
    std::uint64_t timestamp{0U};

    pid_t process_id{0U};
    pid_t thread_id{0U};

    uid_t user_id{0U};
    gid_t group_id{0U};

    std::int64_t exit_code{0};
    bool probe_error{false};

    std::string executable_path;
    std::string cmdline;
  };

  using SyscallEventList = std::vector<SyscallEvent>;

  SyscallEventList event_list;
};

class BPFProcessEventsPublisher final
    : public EventPublisher<BPFProcessEventsSC, BPFProcessEventsEC> {
 public:
  BPFProcessEventsPublisher();
  virtual ~BPFProcessEventsPublisher() override;

  void eventCallback(
      const tob::ebpfpub::IFunctionSerializer::EventList& event_list);

  virtual Status setUp() override;
  virtual void configure() override;
  virtual Status run() override;
  virtual void tearDown() override;

 private:
  DECLARE_PUBLISHER("BPFProcessEventsPublisher");

  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  BPFProcessEventsEC::SyscallEventList generateSyscallEventList(
      const tob::ebpfpub::IFunctionSerializer::EventList& event_list);
};
} // namespace osquery
