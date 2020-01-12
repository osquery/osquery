/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <cstdint>
#include <limits>
#include <memory>
#include <unordered_map>

#include <boost/variant.hpp>

#include <osquery/core/flags.h>
#include <osquery/events/containerd/client_interface.h>
#include <osquery/events/eventpublisher.h>

namespace osquery {

class BaseContainerEvent {
 public:
  enum class Type {
    ContainerEvent,
    ContentEvent,
    ImageEvent,
    NamespaceEvent,
    SnapshotEvent,
    TaskEvent
  };

  BaseContainerEvent(Type type,
                     const std::string& timestamp,
                     const std::string& namespace_name,
                     const std::string& topic)
      : type_(type),
        timestamp_(timestamp),
        namespace_name_(namespace_name),
        topic_(topic) {}

  Type type_;
  std::string timestamp_;
  std::string namespace_name_;
  std::string topic_;

  virtual ~BaseContainerEvent(){};
};

class ContainerEvent final : public BaseContainerEvent {
 public:
  struct RuncOptions {
    std::string runtime_;
    std::string runtime_root_;
    std::string criu_path_;
    bool systemd_cgroup_;
  };
  ContainerEvent() = delete;
  ContainerEvent(const std::string& timestamp,
                 const std::string& namespace_name,
                 const std::string& topic,
                 const std::string& container_id,
                 const std::string& image_name,
                 RuncOptions runtime,
                 const std::string& snapshot_key,
                 std::unordered_map<std::string, std::string> labels)
      : BaseContainerEvent(
            Type::ContainerEvent, timestamp, namespace_name, topic),
        container_id_(container_id),
        image_name_(image_name),
        runtime_(std::move(runtime)),
        snapshot_key_(snapshot_key),
        labels_(std::move(labels)) {}

  std::string container_id_;
  std::string image_name_;
  RuncOptions runtime_;
  std::string snapshot_key_;
  std::unordered_map<std::string, std::string> labels_;
};

class ContentEvent final : public BaseContainerEvent {
 public:
  ContentEvent(const std::string& timestamp,
               const std::string& namespace_name,
               const std::string& topic,
               const std::string& digest)
      : BaseContainerEvent(
            Type::ContentEvent, timestamp, namespace_name, topic),
        digest_(digest) {}
  std::string digest_;
};

class ImageEvent final : public BaseContainerEvent {
 public:
  ImageEvent(const std::string& timestamp,
             const std::string& namespace_name,
             const std::string& topic,
             const std::string& name,
             std::unordered_map<std::string, std::string> labels)
      : BaseContainerEvent(Type::ImageEvent, timestamp, namespace_name, topic),
        name_(name),
        labels_(std::move(labels)) {}

  std::string name_;
  std::unordered_map<std::string, std::string> labels_;
};

class NamespaceEvent final : public BaseContainerEvent {
 public:
  NamespaceEvent(const std::string& timestamp,
                 const std::string& namespace_name,
                 const std::string& topic,
                 const std::string& name,
                 std::unordered_map<std::string, std::string> labels)
      : BaseContainerEvent(
            Type::NamespaceEvent, timestamp, namespace_name, topic),
        name_(name),
        labels_(std::move(labels)) {}

  std::string name_;
  std::unordered_map<std::string, std::string> labels_;
};

class SnapshotEvent final : public BaseContainerEvent {
 public:
  SnapshotEvent(const std::string& timestamp,
                const std::string& namespace_name,
                const std::string& topic,
                const std::string& key,
                const std::string& name,
                const std::string& parent)
      : BaseContainerEvent(
            Type::SnapshotEvent, timestamp, namespace_name, topic),
        key_(key),
        name_(name),
        parent_(parent) {}

  std::string key_;
  std::string name_;
  std::string parent_;
};

class TaskEvent final : public BaseContainerEvent {
 public:
  struct Mount {
    std::string type_;
    std::string source_;
    std::string target_;
    std::string options_;
  };

  struct TaskIO {
    std::string stdin_;
    std::string stdout_;
    std::string stderr_;
    bool terminal_{false};
  };

  TaskEvent(const std::string& timestamp,
            const std::string& namespace_name,
            const std::string& topic,
            const std::string& container_id,
            const std::string& bundle,
            std::vector<Mount> rootfs,
            TaskIO io,
            const std::string& checkpoint,
            uint32_t pid,
            uint32_t exit_status,
            const std::string& exited_at,
            const std::string& exec_id)
      : BaseContainerEvent(Type::TaskEvent, timestamp, namespace_name, topic),
        container_id_(container_id),
        bundle_(bundle),
        rootfs_(std::move(rootfs)),
        io_(std::move(io)),
        checkpoint_(checkpoint),
        pid_(pid),
        exit_status_(exit_status),
        exited_at_(exited_at),
        exec_id_(exec_id) {}

  std::string container_id_;
  std::string bundle_;
  std::vector<Mount> rootfs_;
  TaskIO io_;
  std::string checkpoint_;
  uint32_t pid_;
  uint32_t exit_status_;
  std::string exited_at_;
  std::string exec_id_;
};

struct ContainerSubscriptionContext final : public SubscriptionContext {
 public:
  ContainerEvent::Type event_type_subscription;

 private:
  friend class ContainerEventPublisher;
};

struct ContainerEventContext final : public EventContext {
  std::unique_ptr<BaseContainerEvent> container_event;
};

using ContainerSubscriptionContextRef =
    std::shared_ptr<ContainerSubscriptionContext>;
using ContainerEventContextRef = std::shared_ptr<ContainerEventContext>;

class ContainerEventPublisher final
    : public EventPublisher<ContainerSubscriptionContext,
                            ContainerEventContext> {
  DECLARE_PUBLISHER("containerevent");

 public:
  Status setUp() override;
  void configure() override;
  void tearDown() override;
  bool shouldFire(const ContainerSubscriptionContextRef& sc,
                  const ContainerEventContextRef& ec) const override;
  Status run() override;

  virtual ~ContainerEventPublisher() {
    tearDown();
  }

 private:
  IAsyncAPIClientRef rpc_client_;
  IQueryEventRequestOutputRef output_;

  std::string socket_addr_;
};

} // namespace osquery
