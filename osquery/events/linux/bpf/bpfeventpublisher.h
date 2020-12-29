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

#include <ebpfpub/ifunctiontracer.h>
#include <ebpfpub/iperfeventreader.h>

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
  template <typename T>
  static bool getEventMapValue(
      T& value,
      const tob::ebpfpub::IFunctionTracer::Event::FieldMap& field_map,
      const std::string& key) {
    auto field_it = field_map.find(key);
    if (field_it == field_map.end()) {
      return false;
    }

    const auto& var = field_it->second.data_var;
    if (!std::holds_alternative<T>(var)) {
      return false;
    }

    value = std::get<T>(var);
    return true;
  }

  static bool processForkEvent(
      ISystemStateTracker& state,
      const tob::ebpfpub::IFunctionTracer::Event& event);

  static bool processVforkEvent(
      ISystemStateTracker& state,
      const tob::ebpfpub::IFunctionTracer::Event& event);

  static bool processCloneEvent(
      ISystemStateTracker& state,
      const tob::ebpfpub::IFunctionTracer::Event& event);

  static bool processExecveEvent(
      ISystemStateTracker& state,
      const tob::ebpfpub::IFunctionTracer::Event& event);

  static bool processExecveatEvent(
      ISystemStateTracker& state,
      const tob::ebpfpub::IFunctionTracer::Event& event);

  static bool processCloseEvent(
      ISystemStateTracker& state,
      const tob::ebpfpub::IFunctionTracer::Event& event);

  static bool processDupEvent(
      ISystemStateTracker& state,
      const tob::ebpfpub::IFunctionTracer::Event& event);

  static bool processDup2Event(
      ISystemStateTracker& state,
      const tob::ebpfpub::IFunctionTracer::Event& event);

  static bool processDup3Event(
      ISystemStateTracker& state,
      const tob::ebpfpub::IFunctionTracer::Event& event);

  static bool processNameToHandleAtEvent(
      ISystemStateTracker& state,
      const tob::ebpfpub::IFunctionTracer::Event& event);

  static bool processOpenByHandleAtEvent(
      ISystemStateTracker& state,
      const tob::ebpfpub::IFunctionTracer::Event& event);

  static bool processCreatEvent(
      ISystemStateTracker& state,
      const tob::ebpfpub::IFunctionTracer::Event& event);

  static bool processMknodatEvent(
      ISystemStateTracker& state,
      const tob::ebpfpub::IFunctionTracer::Event& event);

  static bool processOpenEvent(
      ISystemStateTracker& state,
      const tob::ebpfpub::IFunctionTracer::Event& event);

  static bool processOpenatEvent(
      ISystemStateTracker& state,
      const tob::ebpfpub::IFunctionTracer::Event& event);

  static bool processOpenat2Event(
      ISystemStateTracker& state,
      const tob::ebpfpub::IFunctionTracer::Event& event);

  static bool processChdirEvent(
      ISystemStateTracker& state,
      const tob::ebpfpub::IFunctionTracer::Event& event);

  static bool processFchdirEvent(
      ISystemStateTracker& state,
      const tob::ebpfpub::IFunctionTracer::Event& event);

  static bool processSocketEvent(
      ISystemStateTracker& state,
      const tob::ebpfpub::IFunctionTracer::Event& event);

  static bool processFcntlEvent(
      ISystemStateTracker& state,
      const tob::ebpfpub::IFunctionTracer::Event& event);

  static bool processConnectEvent(
      ISystemStateTracker& state,
      const tob::ebpfpub::IFunctionTracer::Event& event);

  static bool processAcceptEvent(
      ISystemStateTracker& state,
      const tob::ebpfpub::IFunctionTracer::Event& event);

  static bool processAccept4Event(
      ISystemStateTracker& state,
      const tob::ebpfpub::IFunctionTracer::Event& event);

  static bool processBindEvent(
      ISystemStateTracker& state,
      const tob::ebpfpub::IFunctionTracer::Event& event);

  static bool processListenEvent(
      ISystemStateTracker& state,
      const tob::ebpfpub::IFunctionTracer::Event& event);
};

} // namespace osquery
