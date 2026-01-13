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
#include <osquery/events/linux/bpf/isystemstatetracker.h>

#include <vector>

namespace osquery {

struct BPFEventSC final : public SubscriptionContext {
 private:
  friend class BPFEventPublisher;
};

struct BPFEventEC final : public EventContext {
  ISystemStateTracker::EventList event_list;
};

class BPFEventPublisher final : public EventPublisher<BPFEventSC, BPFEventEC> {
 public:
  BPFEventPublisher();
  virtual ~BPFEventPublisher() override;

  virtual Status setUp() override;
  virtual void configure() override;
  virtual Status run() override;
  virtual void tearDown() override;

 private:
  DECLARE_PUBLISHER("BPFEventPublisher");

  struct PrivateData;
  std::unique_ptr<PrivateData> d;

 public:
  // ebpfpub removed - methods that depended on it have been removed
};

} // namespace osquery
