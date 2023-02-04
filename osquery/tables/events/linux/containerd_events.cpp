/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/flags.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sql.h>

#include <boost/algorithm/string/join.hpp>

#include <osquery/events/eventpublisher.h>
#include <osquery/events/eventsubscriber.h>
#include <osquery/events/linux/containereventpublisher.h>

namespace osquery {

namespace {
std::string labelsMapToString(
    std::unordered_map<std::string, std::string> labels) {
  std::string labels_string;
  for (const auto& label_pair : labels) {
    labels_string += label_pair.first + "=" + label_pair.second + ",";
  }

  if (!labels_string.empty()) {
    labels_string.pop_back();
  }
  return labels_string;
}
} // namespace

class ContainerdContainerEventSubscriber final
    : public EventSubscriber<ContainerEventPublisher> {
 public:
  Status init() override;

  Status Callback(const ECRef& ec, const SCRef& sc);
};

REGISTER(ContainerdContainerEventSubscriber,
         "event_subscriber",
         "containerd_container_events");

Status ContainerdContainerEventSubscriber::init() {
  auto subscription = createSubscriptionContext();
  subscription->event_type_subscription =
      BaseContainerEvent::Type::ContainerEvent;

  subscribe(&ContainerdContainerEventSubscriber::Callback, subscription);
  return Status::success();
}

Status ContainerdContainerEventSubscriber::Callback(const ECRef& ec,
                                                    const SCRef& sc) {
  if (ec->container_event->type_ != BaseContainerEvent::Type::ContainerEvent) {
    return Status::failure(
        "Received wrong event type: " +
        std::to_string(static_cast<int>(ec->container_event->type_)));
  }

  Row r;
  const auto& container_event =
      dynamic_cast<const ContainerEvent&>(*ec->container_event);

  r["container_id"] = container_event.container_id_;
  r["timestamp"] = container_event.timestamp_;
  r["namespace"] = container_event.namespace_name_;
  r["topic"] = container_event.topic_;
  r["image_name"] = container_event.image_name_;
  r["runtime"] = container_event.runtime_.runtime_;
  r["runtime_root"] = container_event.runtime_.runtime_root_;
  r["criu_path"] = container_event.runtime_.criu_path_;
  r["systemd_cgroup"] = INTEGER(container_event.runtime_.systemd_cgroup_);
  r["snapshot_key"] = container_event.snapshot_key_;

  std::string labels = labelsMapToString(container_event.labels_);

  r["labels"] = labels;

  add(r);

  return Status::success();
}

class ContainerdContentEventSubscriber final
    : public EventSubscriber<ContainerEventPublisher> {
 public:
  Status init() override;

  Status Callback(const ECRef& ec, const SCRef& sc);
};

REGISTER(ContainerdContentEventSubscriber,
         "event_subscriber",
         "containerd_content_events");

Status ContainerdContentEventSubscriber::init() {
  auto subscription = createSubscriptionContext();
  subscription->event_type_subscription =
      BaseContainerEvent::Type::ContentEvent;

  subscribe(&ContainerdContentEventSubscriber::Callback, subscription);
  return Status::success();
}

Status ContainerdContentEventSubscriber::Callback(const ECRef& ec,
                                                  const SCRef& sc) {
  if (ec->container_event->type_ != BaseContainerEvent::Type::ContentEvent) {
    return Status::failure(
        "Received wrong event type: " +
        std::to_string(static_cast<int>(ec->container_event->type_)));
  }

  Row r;
  const auto& content_event =
      dynamic_cast<const ContentEvent&>(*ec->container_event);

  r["timestamp"] = content_event.timestamp_;
  r["namespace"] = content_event.namespace_name_;
  r["topic"] = content_event.topic_;
  r["digest"] = content_event.digest_;

  add(r);

  return Status::success();
}

class ContainerdImageEventSubscriber final
    : public EventSubscriber<ContainerEventPublisher> {
 public:
  Status init() override;

  Status Callback(const ECRef& ec, const SCRef& sc);
};

REGISTER(ContainerdImageEventSubscriber,
         "event_subscriber",
         "containerd_image_events");

Status ContainerdImageEventSubscriber::init() {
  auto subscription = createSubscriptionContext();
  subscription->event_type_subscription = BaseContainerEvent::Type::ImageEvent;

  subscribe(&ContainerdImageEventSubscriber::Callback, subscription);
  return Status::success();
}

Status ContainerdImageEventSubscriber::Callback(const ECRef& ec,
                                                const SCRef& sc) {
  if (ec->container_event->type_ != BaseContainerEvent::Type::ImageEvent) {
    return Status::failure(
        "Received wrong event type: " +
        std::to_string(static_cast<int>(ec->container_event->type_)));
  }

  Row r;
  const auto& image_event =
      dynamic_cast<const ImageEvent&>(*ec->container_event);

  r["timestamp"] = image_event.timestamp_;
  r["namespace"] = image_event.namespace_name_;
  r["topic"] = image_event.topic_;
  r["name"] = image_event.name_;

  std::string labels = labelsMapToString(image_event.labels_);

  r["labels"] = labels;

  add(r);

  return Status::success();
}

class ContainerdNamespaceEventSubscriber final
    : public EventSubscriber<ContainerEventPublisher> {
 public:
  Status init() override;

  Status Callback(const ECRef& ec, const SCRef& sc);
};

REGISTER(ContainerdNamespaceEventSubscriber,
         "event_subscriber",
         "containerd_namespace_events");

Status ContainerdNamespaceEventSubscriber::init() {
  auto subscription = createSubscriptionContext();
  subscription->event_type_subscription =
      BaseContainerEvent::Type::NamespaceEvent;

  subscribe(&ContainerdNamespaceEventSubscriber::Callback, subscription);
  return Status::success();
}

Status ContainerdNamespaceEventSubscriber::Callback(const ECRef& ec,
                                                    const SCRef& sc) {
  if (ec->container_event->type_ != BaseContainerEvent::Type::NamespaceEvent) {
    return Status::failure(
        "Received wrong event type: " +
        std::to_string(static_cast<int>(ec->container_event->type_)));
  }

  Row r;
  const auto& namespace_event =
      dynamic_cast<const NamespaceEvent&>(*ec->container_event);

  r["timestamp"] = namespace_event.timestamp_;
  r["namespace"] = namespace_event.namespace_name_;
  r["topic"] = namespace_event.topic_;
  r["name"] = namespace_event.name_;

  std::string labels = labelsMapToString(namespace_event.labels_);

  r["labels"] = labels;

  add(r);

  return Status::success();
}

class ContainerdSnapshotEventSubscriber final
    : public EventSubscriber<ContainerEventPublisher> {
 public:
  Status init() override;

  Status Callback(const ECRef& ec, const SCRef& sc);
};

REGISTER(ContainerdSnapshotEventSubscriber,
         "event_subscriber",
         "containerd_snapshot_events");

Status ContainerdSnapshotEventSubscriber::init() {
  auto subscription = createSubscriptionContext();
  subscription->event_type_subscription =
      BaseContainerEvent::Type::SnapshotEvent;

  subscribe(&ContainerdSnapshotEventSubscriber::Callback, subscription);
  return Status::success();
}

Status ContainerdSnapshotEventSubscriber::Callback(const ECRef& ec,
                                                   const SCRef& sc) {
  if (ec->container_event->type_ != BaseContainerEvent::Type::SnapshotEvent) {
    return Status::failure(
        "Received wrong event type: " +
        std::to_string(static_cast<int>(ec->container_event->type_)));
  }

  Row r;
  const auto& snapshot_event =
      dynamic_cast<const SnapshotEvent&>(*ec->container_event);

  r["timestamp"] = snapshot_event.timestamp_;
  r["namespace"] = snapshot_event.namespace_name_;
  r["topic"] = snapshot_event.topic_;
  r["key"] = snapshot_event.key_;
  r["name"] = snapshot_event.name_;
  r["parent"] = snapshot_event.parent_;

  add(r);

  return Status::success();
}

class ContainerdTaskEventSubscriber final
    : public EventSubscriber<ContainerEventPublisher> {
 public:
  Status init() override;

  Status Callback(const ECRef& ec, const SCRef& sc);
};

REGISTER(ContainerdTaskEventSubscriber,
         "event_subscriber",
         "containerd_task_events");

Status ContainerdTaskEventSubscriber::init() {
  auto subscription = createSubscriptionContext();
  subscription->event_type_subscription = BaseContainerEvent::Type::TaskEvent;

  subscribe(&ContainerdTaskEventSubscriber::Callback, subscription);
  return Status::success();
}

Status ContainerdTaskEventSubscriber::Callback(const ECRef& ec,
                                               const SCRef& sc) {
  if (ec->container_event->type_ != BaseContainerEvent::Type::TaskEvent) {
    return Status::failure(
        "Received wrong event type: " +
        std::to_string(static_cast<int>(ec->container_event->type_)));
  }

  const auto& task_event = dynamic_cast<const TaskEvent&>(*ec->container_event);

  Row r;
  r["timestamp"] = task_event.timestamp_;
  r["namespace"] = task_event.namespace_name_;
  r["topic"] = task_event.topic_;
  r["container_id"] = task_event.container_id_;
  r["bundle"] = task_event.bundle_;
  r["io_stdin"] = task_event.io_.stdin_;
  r["io_stdout"] = task_event.io_.stdout_;
  r["io_stderr"] = task_event.io_.stderr_;
  r["io_terminal"] = INTEGER(task_event.io_.terminal_);
  r["checkpoint"] = task_event.checkpoint_;
  r["pid"] = INTEGER(task_event.pid_);
  r["exit_status"] = INTEGER(task_event.exit_status_);
  r["exited_at"] = task_event.exited_at_;
  r["exec_id"] = task_event.exec_id_;

  if (task_event.rootfs_.empty()) {
    add(r);
  } else {
    for (const auto& mount : task_event.rootfs_) {
      r["rootfs_type"] = mount.type_;
      r["rootfs_options"] = mount.options_;
      r["rootfs_source"] = mount.source_;
      r["rootfs_target"] = mount.target_;
      add(r);
    }
  }

  return Status::success();
}

} // namespace osquery
