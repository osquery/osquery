/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <regex>
#include <unordered_map>

#include <boost/asio.hpp>

#include <grpcpp/grpcpp.h>

#include <google/protobuf/util/time_util.h>

#include <osquery/core/flags.h>
#include <osquery/events/containerd/container.grpc.pb.h>
#include <osquery/events/containerd/content.grpc.pb.h>
#include <osquery/events/containerd/image.grpc.pb.h>
#include <osquery/events/containerd/namespace.grpc.pb.h>
#include <osquery/events/containerd/runc.grpc.pb.h>
#include <osquery/events/containerd/snapshot.grpc.pb.h>
#include <osquery/events/containerd/task.grpc.pb.h>
#include <osquery/events/eventsubscriber.h>
#include <osquery/events/linux/containereventpublisher.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/json/json.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

namespace local = boost::asio::local;

namespace osquery {

const std::string kContainerEventTypePrefix = "containerd.events.Container";
const std::string kContentEventTypePrefix = "containerd.events.Content";
const std::string kImageEventTypePrefix = "containerd.events.Image";
const std::string kNamespaceEventTypePrefix = "containerd.events.Namespace";
const std::string kSnapshotEventTypePrefix = "containerd.events.Snapshot";
const std::string kTaskEventTypePrefix = "containerd.events.Task";

REGISTER(ContainerEventPublisher, "event_publisher", "containerevent");

FLAG(string,
     containerd_socket,
     "/run/containerd/containerd.sock",
     "Docker UNIX domain socket path");

FLAG(string,
     containerd_events_namespaces,
     "",
     "Comma separated list of namespaces to receive events from, empty means "
     "all");

FLAG(bool,
     enable_containerd_events_publisher,
     false,
     "Enable the containerd event publisher");

namespace {
bool IsPublisherEnabled() noexcept {
  return FLAGS_enable_containerd_events_publisher;
}

template <typename T, typename... ConstructorArgs>
auto createContainerEvent(
    const containerd::services::events::v1::Envelope& event,
    ConstructorArgs&&... args) {
  return std::make_unique<T>(
      google::protobuf::util::TimeUtil::ToString(event.timestamp()),
      event.namespace_(),
      event.topic(),
      std::forward<ConstructorArgs>(args)...);
}

std::unordered_map<std::string, std::string> labelsProtobufMapToUnorderedMap(
    const google::protobuf::Map<std::string, std::string>& protobuf_map) {
  std::unordered_map<std::string, std::string> labels;

  for (const auto& label_pair : protobuf_map) {
    labels.emplace(label_pair.first, label_pair.second);
  }

  return labels;
}

} // namespace

Status ContainerEventPublisher::setUp() {
  if (!IsPublisherEnabled()) {
    return Status::failure("Publisher disabled via configuration");
  }

  grpc_init();

  return Status::success();
}

void ContainerEventPublisher::configure() {
  if (!IsPublisherEnabled()) {
    return;
  }

  auto status =
      createAsyncAPIClient(rpc_client_, "unix://" + FLAGS_containerd_socket);

  if (!status.ok()) {
    LOG(ERROR) << "Failed to create a client to the containerd socket: "
               << status.getMessage();
    return;
  }

  containerd::services::events::v1::SubscribeRequest subscribe_request;

  if (!FLAGS_containerd_events_namespaces.empty()) {
    std::vector<std::string> filters;
    boost::algorithm::split(filters,
                            FLAGS_containerd_events_namespaces,
                            boost::algorithm::is_any_of(","));
    for (const auto& filter : filters) {
      subscribe_request.add_filters("namespace==" + filter);
    }
  }

  output_ = rpc_client_->subscribeEvents(subscribe_request);

  if (!output_->running()) {
    auto status = output_->status().get();
    LOG(INFO) << "Publisher failed: " << status.getCode() << " "
              << status.getMessage();
  }
}

void ContainerEventPublisher::tearDown() {
  if (!IsPublisherEnabled()) {
    return;
  }

  if (rpc_client_ != nullptr) {
    rpc_client_.reset();
    grpc_shutdown();
  }
}

bool ContainerEventPublisher::shouldFire(
    const ContainerSubscriptionContextRef& sc,
    const ContainerEventContextRef& ec) const {
  if (ec->container_event == nullptr)
    return false;

  return sc->event_type_subscription == ec->container_event->type_;
}

void parseContainerEvent(ContainerEventContextRef event_context,
                         containerd::services::events::v1::Envelope event,
                         const std::string& event_type) {
  if (event_type == "Create") {
    containerd::events::ContainerCreate container_create;
    container_create.ParseFromString(event.event().value());

    ContainerEvent::RuncOptions event_runc_options{};
    if (container_create.runtime().options().type_url() ==
        "containerd.linux.runc.RuncOptions") {
      containerd::linux_runtime::runc::RuncOptions runc_options;
      runc_options.ParseFromString(
          container_create.runtime().options().value());

      event_runc_options.runtime_ = runc_options.runtime();
      event_runc_options.runtime_root_ = runc_options.runtime_root();
      event_runc_options.criu_path_ = runc_options.criu_path();
      event_runc_options.systemd_cgroup_ = runc_options.systemd_cgroup();
    } else {
      LOG(INFO) << "Options type "
                << container_create.runtime().options().type_url()
                << " not supported";
    }

    event_context->container_event = createContainerEvent<ContainerEvent>(
        event,
        container_create.id(),
        container_create.image(),
        std::move(event_runc_options),
        "",
        std::unordered_map<std::string, std::string>{});
  } else if (event_type == "Update") {
    containerd::events::ContainerUpdate container_update;
    container_update.ParseFromString(event.event().value());

    auto labels = labelsProtobufMapToUnorderedMap(container_update.labels());

    event_context->container_event =
        createContainerEvent<ContainerEvent>(event,
                                             container_update.id(),
                                             container_update.image(),
                                             ContainerEvent::RuncOptions{},
                                             container_update.snapshot_key(),
                                             std::move(labels));
  } else if (event_type == "Delete") {
    containerd::events::ContainerDelete container_delete;
    container_delete.ParseFromString(event.event().value());

    event_context->container_event = createContainerEvent<ContainerEvent>(
        event,
        container_delete.id(),
        "",
        ContainerEvent::RuncOptions{},
        "",
        std::unordered_map<std::string, std::string>{});
  }
}

void parseContentEvent(ContainerEventContextRef event_context,
                       containerd::services::events::v1::Envelope event,
                       const std::string& event_type) {
  if (event_type == "Delete") {
    containerd::events::ContentDelete content_delete;
    content_delete.ParseFromString(event.event().value());

    event_context->container_event =
        createContainerEvent<ContentEvent>(event, content_delete.digest());
  }
}

void parseImageEvent(ContainerEventContextRef event_context,
                     containerd::services::events::v1::Envelope event,
                     const std::string& event_type) {
  if (event_type == "Create") {
    containerd::services::images::v1::ImageCreate image_create;
    image_create.ParseFromString(event.event().value());

    auto labels = labelsProtobufMapToUnorderedMap(image_create.labels());

    event_context->container_event = createContainerEvent<ImageEvent>(
        event, image_create.name(), std::move(labels));

  } else if (event_type == "Update") {
    containerd::services::images::v1::ImageUpdate image_update;
    image_update.ParseFromString(event.event().value());

    auto labels = labelsProtobufMapToUnorderedMap(image_update.labels());

    event_context->container_event = createContainerEvent<ImageEvent>(
        event, image_update.name(), std::move(labels));

  } else if (event_type == "Delete") {
    containerd::services::images::v1::ImageDelete image_delete;
    image_delete.ParseFromString(event.event().value());

    event_context->container_event = createContainerEvent<ImageEvent>(
        event,
        image_delete.name(),
        std::unordered_map<std::string, std::string>{});
  }
}

void parseNamespaceEvent(ContainerEventContextRef event_context,
                         containerd::services::events::v1::Envelope event,
                         const std::string& event_type) {
  if (event_type == "Create") {
    containerd::events::NamespaceCreate namespace_create;
    namespace_create.ParseFromString(event.event().value());

    auto labels = labelsProtobufMapToUnorderedMap(namespace_create.labels());

    event_context->container_event = createContainerEvent<NamespaceEvent>(
        event, namespace_create.name(), std::move(labels));

  } else if (event_type == "Update") {
    containerd::events::NamespaceUpdate namespace_update;
    namespace_update.ParseFromString(event.event().value());

    auto labels = labelsProtobufMapToUnorderedMap(namespace_update.labels());

    event_context->container_event = createContainerEvent<NamespaceEvent>(
        event, namespace_update.name(), std::move(labels));

  } else if (event_type == "Delete") {
    containerd::events::NamespaceDelete namespace_delete;
    namespace_delete.ParseFromString(event.event().value());

    event_context->container_event = createContainerEvent<NamespaceEvent>(
        event,
        namespace_delete.name(),
        std::unordered_map<std::string, std::string>{});
  }
}

void parseSnapshotEvent(ContainerEventContextRef event_context,
                        containerd::services::events::v1::Envelope event,
                        const std::string& event_type) {
  if (event_type == "Prepare") {
    containerd::events::SnapshotPrepare snapshot_prepare;
    snapshot_prepare.ParseFromString(event.event().value());

    event_context->container_event = createContainerEvent<SnapshotEvent>(
        event, snapshot_prepare.key(), "", snapshot_prepare.parent());

  } else if (event_type == "Commit") {
    containerd::events::SnapshotCommit snapshot_commit;
    snapshot_commit.ParseFromString(event.event().value());

    event_context->container_event = createContainerEvent<SnapshotEvent>(
        event, snapshot_commit.key(), snapshot_commit.name(), "");

  } else if (event_type == "Remove") {
    containerd::events::SnapshotRemove snapshot_remove;
    snapshot_remove.ParseFromString(event.event().value());

    event_context->container_event = createContainerEvent<SnapshotEvent>(
        event, snapshot_remove.key(), "", "");
  }
}

void parseTaskEvent(ContainerEventContextRef event_context,
                    containerd::services::events::v1::Envelope event,
                    const std::string& event_type) {
  if (event_type == "Create") {
    containerd::events::TaskCreate task_create;
    task_create.ParseFromString(event.event().value());

    std::vector<TaskEvent::Mount> mounts;
    for (int mount_index = 0; mount_index < task_create.rootfs_size();
         ++mount_index) {
      const auto& current_mount = task_create.rootfs(mount_index);

      JSON options = JSON::newArray();

      for (int option_index = 0; option_index < current_mount.options_size();
           ++option_index) {
        rapidjson::Value option(current_mount.options(option_index),
                                options.doc().GetAllocator());
        options.push(option);
      }

      std::string options_string;
      options.toString(options_string);

      mounts.push_back({current_mount.type(),
                        current_mount.source(),
                        current_mount.target(),
                        options_string});
    }

    event_context->container_event = createContainerEvent<TaskEvent>(
        event,
        task_create.container_id(),
        task_create.bundle(),
        std::move(mounts),
        TaskEvent::TaskIO{task_create.io().stdin(),
                          task_create.io().stdout(),
                          task_create.io().stderr(),
                          task_create.io().terminal()},
        task_create.checkpoint(),
        task_create.pid(),
        0,
        "",
        "");

  } else if (event_type == "Start") {
    containerd::events::TaskStart task_start;
    task_start.ParseFromString(event.event().value());

    event_context->container_event =
        createContainerEvent<TaskEvent>(event,
                                        task_start.container_id(),
                                        "",
                                        std::vector<TaskEvent::Mount>{},
                                        TaskEvent::TaskIO{},
                                        "",
                                        task_start.pid(),
                                        0,
                                        "",
                                        "");
  } else if (event_type == "Delete") {
    containerd::events::TaskDelete task_delete;
    task_delete.ParseFromString(event.event().value());

    event_context->container_event = createContainerEvent<TaskEvent>(
        event,
        task_delete.container_id(),
        "",
        std::vector<TaskEvent::Mount>{},
        TaskEvent::TaskIO{},
        "",
        task_delete.pid(),
        task_delete.exit_status(),
        google::protobuf::util::TimeUtil::ToString(task_delete.exited_at()),
        task_delete.id());
  } else if (event_type == "Exit") {
    containerd::events::TaskExit task_exit;
    task_exit.ParseFromString(event.event().value());

    event_context->container_event = createContainerEvent<TaskEvent>(
        event,
        task_exit.container_id(),
        "",
        std::vector<TaskEvent::Mount>{},
        TaskEvent::TaskIO{},
        "",
        task_exit.pid(),
        task_exit.exit_status(),
        google::protobuf::util::TimeUtil::ToString(task_exit.exited_at()),
        task_exit.id());
  } else if (event_type == "OOM") {
    containerd::events::TaskOOM task_oom;
    task_oom.ParseFromString(event.event().value());

    event_context->container_event =
        createContainerEvent<TaskEvent>(event,
                                        task_oom.container_id(),
                                        "",
                                        std::vector<TaskEvent::Mount>{},
                                        TaskEvent::TaskIO{},
                                        "",
                                        0,
                                        0,
                                        "",
                                        "");
  } else if (event_type == "ExecAdded") {
    containerd::events::TaskExecAdded task_exec_added;
    task_exec_added.ParseFromString(event.event().value());

    event_context->container_event =
        createContainerEvent<TaskEvent>(event,
                                        task_exec_added.container_id(),
                                        "",
                                        std::vector<TaskEvent::Mount>{},
                                        TaskEvent::TaskIO{},
                                        "",
                                        0,
                                        0,
                                        "",
                                        task_exec_added.exec_id());
  } else if (event_type == "ExecStarted") {
    containerd::events::TaskExecStarted task_exec_started;
    task_exec_started.ParseFromString(event.event().value());

    event_context->container_event =
        createContainerEvent<TaskEvent>(event,
                                        task_exec_started.container_id(),
                                        "",
                                        std::vector<TaskEvent::Mount>{},
                                        TaskEvent::TaskIO{},
                                        "",
                                        task_exec_started.pid(),
                                        0,
                                        "",
                                        task_exec_started.exec_id());
  } else if (event_type == "Paused") {
    containerd::events::TaskPaused task_paused;
    task_paused.ParseFromString(event.event().value());

    event_context->container_event =
        createContainerEvent<TaskEvent>(event,
                                        task_paused.container_id(),
                                        "",
                                        std::vector<TaskEvent::Mount>{},
                                        TaskEvent::TaskIO{},
                                        "",
                                        0,
                                        0,
                                        "",
                                        "");
  } else if (event_type == "Resumed") {
    containerd::events::TaskResumed task_resumed;
    task_resumed.ParseFromString(event.event().value());

    event_context->container_event =
        createContainerEvent<TaskEvent>(event,
                                        task_resumed.container_id(),
                                        "",
                                        std::vector<TaskEvent::Mount>{},
                                        TaskEvent::TaskIO{},
                                        "",
                                        0,
                                        0,
                                        "",
                                        "");
  } else if (event_type == "Checkpointed") {
    containerd::events::TaskCheckpointed task_checkpointed;
    task_checkpointed.ParseFromString(event.event().value());

    event_context->container_event =
        createContainerEvent<TaskEvent>(event,
                                        task_checkpointed.container_id(),
                                        "",
                                        std::vector<TaskEvent::Mount>{},
                                        TaskEvent::TaskIO{},
                                        task_checkpointed.checkpoint(),
                                        0,
                                        0,
                                        "",
                                        "");
  }
}

Status ContainerEventPublisher::run() {
  if (!IsPublisherEnabled()) {
    return Status::failure(
        "Container Event Publisher disabled via configuration");
  }

  if (rpc_client_ == nullptr) {
    return Status::failure(
        "The publisher has no client to the containerd socket");
  }

  auto events = output_->getData();
  for (const auto& event : events) {
    auto event_context = createEventContext();
    const auto& type_url = event.event().type_url();

    if (type_url.compare(0,
                         kContainerEventTypePrefix.size(),
                         kContainerEventTypePrefix) == 0) {
      parseContainerEvent(event_context,
                          event,
                          type_url.substr(kContainerEventTypePrefix.size()));

    } else if (type_url.compare(0,
                                kContentEventTypePrefix.size(),
                                kContentEventTypePrefix) == 0) {
      parseContentEvent(event_context,
                        event,
                        type_url.substr(kContentEventTypePrefix.size()));
    } else if (type_url.compare(0,
                                kImageEventTypePrefix.size(),
                                kImageEventTypePrefix) == 0) {
      parseImageEvent(
          event_context, event, type_url.substr(kImageEventTypePrefix.size()));
    } else if (type_url.compare(0,
                                kNamespaceEventTypePrefix.size(),
                                kNamespaceEventTypePrefix) == 0) {
      parseNamespaceEvent(event_context,
                          event,
                          type_url.substr(kNamespaceEventTypePrefix.size()));
    } else if (type_url.compare(0,
                                kSnapshotEventTypePrefix.size(),
                                kSnapshotEventTypePrefix) == 0) {
      parseSnapshotEvent(event_context,
                         event,
                         type_url.substr(kSnapshotEventTypePrefix.size()));
    } else if (type_url.compare(
                   0, kTaskEventTypePrefix.size(), kTaskEventTypePrefix) == 0) {
      parseTaskEvent(
          event_context, event, type_url.substr(kTaskEventTypePrefix.size()));
    }

    fire(event_context);
  }

  return Status::success();
}

} // namespace osquery
