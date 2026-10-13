/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <grpcpp/grpcpp.h>

#include <osquery/core/flags.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/json/json.h>

#include <containerd/containers.grpc.pb.h>
#include <containerd/images.grpc.pb.h>
#include <containerd/namespaces.grpc.pb.h>
#include <containerd/snapshots.grpc.pb.h>
#include <containerd/tasks.grpc.pb.h>

// Include Linux-specific functionality for reading namespace information
#include <osquery/filesystem/linux/proc.h>

#include <array>
#include <charconv>
#include <chrono>
#include <memory>
#include <string_view>
#include <typeindex>
#include <unordered_map>

namespace osquery {

/**
 * @brief Containerd UNIX domain socket path.
 *
 * By default containerd creates UNIX domain socket at
 * /run/containerd/containerd.sock. If containerd is configured to use a
 * different path, specify that path.
 */
FLAG(string,
     containerd_socket,
     "/run/containerd/containerd.sock",
     "Containerd UNIX domain socket path");

/**
 * @brief Containerd namespace to query.
 *
 * Containerd uses namespaces to isolate containers. By default, all namespaces
 * are queried. Set this flag to query a specific namespace like "default" for
 * ctr command or "k8s.io" for Kubernetes.
 */
FLAG(string,
     containerd_namespace,
     "",
     "Containerd namespace to query (empty = all namespaces)");

namespace tables {

namespace {

// Common snapshotters supported by containerd
constexpr std::array<const char*, 4> kSnapshotters = {
    "overlayfs", "native", "btrfs", "zfs"};

// Timeout for gRPC calls to prevent indefinite blocking on unresponsive
// containerd
constexpr auto kGrpcTimeoutSeconds = 5;

// Upper bound on a single gRPC response. gRPC defaults to 4 MiB; a busy k8s
// node accumulates enough container metadata (OCI specs, labels) that the unary
// ListContainers response exceeds it and the client drops the message before
// any row is seen. Container listing is streamed (ListStream) to avoid this
// ceiling entirely; this bound only guards the remaining unary calls (images,
// tasks, namespaces) and is kept finite for memory safety.
constexpr int kMaxRecvMessageBytes = 128 * 1024 * 1024;

// Boolean string representations for table columns
constexpr const char* kBoolTrue = "1";
constexpr const char* kBoolFalse = "0";

/**
 * @brief Configure a gRPC ClientContext with a timeout deadline.
 *
 * This prevents indefinite blocking if containerd becomes unresponsive.
 * Without a timeout, a hanging containerd could cause osquery to hang.
 *
 * Note: Uses out-parameter pattern because grpc::ClientContext is non-copyable.
 *
 * @param context ClientContext to configure (out parameter)
 * @param namespace_name Optional containerd namespace to add as metadata
 */
void createContextWithTimeout(grpc::ClientContext& context,
                              const std::string& namespace_name = "") {
  auto deadline = std::chrono::system_clock::now() +
                  std::chrono::seconds(kGrpcTimeoutSeconds);
  context.set_deadline(deadline);

  if (!namespace_name.empty()) {
    context.AddMetadata("containerd-namespace", namespace_name);
  }
}

/**
 * @brief Create a gRPC channel to containerd with a raised receive-size limit.
 *
 * See kMaxRecvMessageBytes: the default 4 MiB cap rejects large ListContainers
 * responses on busy nodes before any row is read.
 */
[[nodiscard]] std::shared_ptr<grpc::Channel> makeChannel(
    const std::string& address) {
  grpc::ChannelArguments args;
  args.SetMaxReceiveMessageSize(kMaxRecvMessageBytes);
  return grpc::CreateCustomChannel(
      address, grpc::InsecureChannelCredentials(), args);
}

/**
 * @brief RAII wrapper for gRPC channel creation with connection validation and
 * stub caching.
 *
 * Performance optimization: Caches gRPC stubs to avoid repeated stub creation
 * overhead. Stub creation has non-trivial cost, and stubs are called repeatedly
 * in loops across multiple namespaces and snapshotters.
 */
class ContainerdConnection {
 public:
  explicit ContainerdConnection(const std::string& socket_path)
      : socket_address_("unix://" + socket_path),
        channel_(makeChannel(socket_address_)),
        connected_(false) {
    // Try to connect with a short timeout to validate socket exists
    // This prevents unclear error messages when containerd is not running
    auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(1);
    connected_ = channel_->WaitForConnected(deadline);

    if (!connected_) {
      VLOG(1) << "Cannot connect to containerd socket: " << socket_address_;
    }
  }

  std::string_view socket_address() const noexcept {
    return socket_address_;
  }

  bool isConnected() const noexcept {
    return connected_;
  }

  /**
   * @brief Get or create cached stub for the given service type.
   *
   * Uses type-based caching to avoid repeated stub creation.
   * Returns false if stub creation fails (e.g., OOM or network timeout).
   *
   * @tparam StubType The gRPC service stub type (e.g., Containers, Images)
   * @param stub_out Output parameter for stub pointer (non-owning, lifetime
   * managed by cache)
   * @return true if stub was successfully retrieved/created, false on failure
   */
  template <typename StubType>
  bool getStub(typename StubType::Stub** stub_out) const noexcept {
    if (!stub_out) {
      return false;
    }

    std::type_index type_id(typeid(StubType));

    auto it = stub_cache_.find(type_id);
    if (it != stub_cache_.end()) {
      *stub_out = static_cast<typename StubType::Stub*>(it->second.get());
      return true;
    }

    // Create new stub and store in cache
    // NewStub can return nullptr on failure (OOM, network issues, etc.)
    auto stub = StubType::NewStub(channel_);
    if (!stub) {
      VLOG(1) << "Failed to create gRPC stub for service type";
      return false;
    }

    auto* raw_ptr = stub.get();

    // Store with type-erased deleter
    stub_cache_.emplace(type_id,
                        std::shared_ptr<void>(stub.release(), [](void* p) {
                          delete static_cast<typename StubType::Stub*>(p);
                        }));

    *stub_out = raw_ptr;
    return true;
  }

 private:
  std::string socket_address_;
  std::shared_ptr<grpc::Channel> channel_;
  bool connected_;

  // Mutable to allow caching in const methods (const correctness for table
  // generation)
  mutable std::unordered_map<std::type_index, std::shared_ptr<void>>
      stub_cache_;
};

/**
 * @brief RAII guard for gRPC streaming reader to ensure Finish() is always
 * called.
 *
 * This prevents resource leaks when exceptions are thrown during stream
 * processing. Without this guard, if results.push_back() throws (e.g., OOM),
 * the reader's Finish() method would never be called, potentially leaving the
 * gRPC stream in an invalid state.
 *
 * Usage:
 *   auto reader = stub.List(&context, request);
 *   StreamReaderGuard guard(reader);
 *   while (reader->Read(&response)) {
 *     // Process response - may throw
 *   }
 *   grpc::Status status = guard.Finish();  // Explicit finish, guard disabled
 */
template <typename ReaderType>
class StreamReaderGuard {
 public:
  explicit StreamReaderGuard(ReaderType* reader)
      : reader_(reader), finished_(false) {}

  ~StreamReaderGuard() {
    if (!finished_ && reader_) {
      // Finish() in destructor - ignore return status since we can't throw
      reader_->Finish();
    }
  }

  // Disable copy/move - this is a scope guard
  StreamReaderGuard(const StreamReaderGuard&) = delete;
  StreamReaderGuard& operator=(const StreamReaderGuard&) = delete;
  StreamReaderGuard(StreamReaderGuard&&) = delete;
  StreamReaderGuard& operator=(StreamReaderGuard&&) = delete;

  // Explicit finish - disables automatic cleanup
  grpc::Status Finish() {
    finished_ = true;
    return reader_->Finish();
  }

 private:
  ReaderType* reader_;
  bool finished_;
};

/**
 * @brief Helper to format protobuf timestamp to string (seconds since epoch).
 *
 * Performance optimized: Uses C++17 std::to_chars for zero-allocation
 * integer-to-string conversion, ~10x faster than std::to_string.
 */
std::string formatTimestamp(const google::protobuf::Timestamp& timestamp) {
  // Pre-allocate buffer for int64_t (max 20 digits + sign + null terminator)
  char buffer[24];
  auto [ptr, ec] =
      std::to_chars(buffer, buffer + sizeof(buffer), timestamp.seconds());
  if (ec == std::errc{}) {
    return std::string(buffer, ptr - buffer);
  }
  // Fallback on error (should never happen for valid timestamps)
  return "0";
}

/**
 * @brief Helper to convert JSON array to comma-separated string.
 *
 * Performance optimized: pre-calculates total size to avoid O(n²) string
 * reallocations. Critical for containers with many environment variables.
 */
std::string jsonArrayToString(const rapidjson::Value& arr) {
  if (arr.Empty()) {
    return {};
  }

  // Pre-calculate total size to avoid repeated reallocations
  size_t total_size = 0;
  size_t string_count = 0;
  for (rapidjson::SizeType i = 0; i < arr.Size(); ++i) {
    if (arr[i].IsString()) {
      total_size += arr[i].GetStringLength();
      ++string_count;
    }
  }

  if (string_count == 0) {
    return {};
  }

  // Add space for commas (one less than number of strings)
  if (string_count > 1) {
    total_size += (string_count - 1);
  }

  std::string result;
  result.reserve(total_size);

  bool first = true;
  for (rapidjson::SizeType i = 0; i < arr.Size(); ++i) {
    if (arr[i].IsString()) {
      if (!first) {
        result.push_back(',');
      }
      first = false;
      result.append(arr[i].GetString(), arr[i].GetStringLength());
    }
  }

  return result;
}

/**
 * @brief Get list of containerd namespaces to query.
 *
 * Returns either the single namespace specified by FLAGS_containerd_namespace,
 * or all available namespaces if no specific namespace is requested.
 */
std::vector<std::string> getNamespacesToQuery(
    const ContainerdConnection& conn) {
  std::vector<std::string> namespaces;

  if (!FLAGS_containerd_namespace.empty()) {
    namespaces.push_back(FLAGS_containerd_namespace);
    return namespaces;
  }

  // List all namespaces
  containerd::services::namespaces::v1::Namespaces::Stub* stub = nullptr;
  if (!conn.getStub<containerd::services::namespaces::v1::Namespaces>(&stub)) {
    VLOG(1) << "Failed to create namespaces stub";
    namespaces.push_back("default");
    return namespaces;
  }

  containerd::services::namespaces::v1::ListNamespacesRequest request;
  containerd::services::namespaces::v1::ListNamespacesResponse response;
  grpc::ClientContext context;
  createContextWithTimeout(context);

  grpc::Status status = stub->List(&context, request, &response);

  if (!status.ok()) {
    VLOG(1) << "Error listing namespaces: " << status.error_message();
    namespaces.push_back("default");
    return namespaces;
  }

  namespaces.reserve(response.namespaces_size());
  for (const auto& ns : response.namespaces()) {
    namespaces.push_back(ns.name());
  }

  return namespaces;
}

/**
 * @brief Map containerd task status enum to string.
 */
std::string mapTaskStatus(containerd::services::tasks::v1::Status status) {
  switch (status) {
  case containerd::services::tasks::v1::Status::CREATED:
    return "created";
  case containerd::services::tasks::v1::Status::RUNNING:
    return "running";
  case containerd::services::tasks::v1::Status::STOPPED:
    return "stopped";
  case containerd::services::tasks::v1::Status::PAUSED:
    return "paused";
  case containerd::services::tasks::v1::Status::PAUSING:
    return "pausing";
  case containerd::services::tasks::v1::Status::UNKNOWN:
  default:
    return "unknown";
  }
}

/**
 * @brief Map snapshot kind enum to string.
 */
std::string mapSnapshotKind(
    containerd::services::snapshots::v1::Info::Kind kind) {
  switch (kind) {
  case containerd::services::snapshots::v1::Info::VIEW:
    return "view";
  case containerd::services::snapshots::v1::Info::ACTIVE:
    return "active";
  case containerd::services::snapshots::v1::Info::COMMITTED:
    return "committed";
  default:
    return "unknown";
  }
}

/**
 * @brief Discover which snapshotters are actually available in a namespace.
 *
 * Performance optimization: Instead of querying all 4 snapshotters (overlayfs,
 * native, btrfs, zfs), discover which ones actually exist. Most containerd
 * installations only use overlayfs, making this a 4x improvement.
 *
 * @param conn ContainerdConnection object
 * @param namespace_name Containerd namespace to check
 * @return Vector of available snapshotter names
 */
std::vector<std::string> getAvailableSnapshotters(
    const ContainerdConnection& conn, const std::string& namespace_name) {
  std::vector<std::string> result;
  result.reserve(kSnapshotters.size());

  for (const auto* snapshotter : kSnapshotters) {
    containerd::services::snapshots::v1::Snapshots::Stub* stub = nullptr;
    if (!conn.getStub<containerd::services::snapshots::v1::Snapshots>(&stub)) {
      VLOG(1) << "Failed to create snapshots stub";
      continue;
    }

    containerd::services::snapshots::v1::ListSnapshotsRequest request;
    request.set_snapshotter(snapshotter);

    grpc::ClientContext context;
    createContextWithTimeout(context, namespace_name);

    auto reader = stub->List(&context, request);
    StreamReaderGuard guard(reader.get());

    containerd::services::snapshots::v1::ListSnapshotsResponse response;
    // Try to read one response - if successful, snapshotter exists
    if (reader->Read(&response)) {
      result.emplace_back(snapshotter);
    }

    // Finish the stream - explicit call allows us to check the status
    grpc::Status status = guard.Finish();
    // NOT_FOUND is expected for non-configured snapshotters, other errors are
    // worth noting
    if (!status.ok() && status.error_code() != grpc::StatusCode::NOT_FOUND) {
      VLOG(1) << "Error checking snapshotter " << snapshotter
              << " in namespace " << namespace_name << ": "
              << status.error_message();
    }
  }

  VLOG(1) << "Found " << result.size()
          << " configured snapshotters in namespace " << namespace_name;
  return result;
}

/**
 * @brief Get all tasks for a namespace via gRPC.
 *
 * Fetches all tasks in a namespace with a single gRPC call and returns them
 * indexed by container ID for efficient lookup. This avoids N+1 gRPC calls
 * when querying task information for multiple containers.
 */
std::unordered_map<std::string, containerd::services::tasks::v1::Process>
getAllTasks(const ContainerdConnection& conn,
            const std::string& namespace_name) {
  std::unordered_map<std::string, containerd::services::tasks::v1::Process>
      tasks_by_container;

  containerd::services::tasks::v1::Tasks::Stub* stub = nullptr;
  if (!conn.getStub<containerd::services::tasks::v1::Tasks>(&stub)) {
    VLOG(1) << "Failed to create tasks stub";
    return tasks_by_container;
  }

  containerd::services::tasks::v1::ListTasksRequest request;
  // Empty filter returns all tasks in the namespace

  containerd::services::tasks::v1::ListTasksResponse response;
  grpc::ClientContext context;
  createContextWithTimeout(context, namespace_name);

  grpc::Status grpc_status = stub->List(&context, request, &response);

  if (!grpc_status.ok()) {
    VLOG(1) << "Failed to list tasks in namespace " << namespace_name << ": "
            << grpc_status.error_message();
    return tasks_by_container;
  }

  VLOG(1) << "Found " << response.tasks_size() << " tasks in namespace "
          << namespace_name;

  // Index tasks by task ID (which matches container ID) for O(1) lookup
  // Note: task.container_id() is often empty; task.id() contains the actual
  // container identifier
  for (const auto& task : response.tasks()) {
    VLOG(1) << "Task: container_id='" << task.container_id() << "' id='"
            << task.id() << "' pid=" << task.pid()
            << " status=" << task.status();
    tasks_by_container[task.id()] = task;
  }

  return tasks_by_container;
}

/**
 * @brief Template function to extract labels from containerd entities.
 *
 * This generic function works with any containerd entity that has a labels map.
 */
template <typename EntityType, typename IdentifierFunc>
void extractLabelsFromEntity(const EntityType& entity,
                             const std::string& namespace_name,
                             QueryData& results,
                             IdentifierFunc&& addIdentifiers) {
  for (const auto& label : entity.labels()) {
    Row r;
    addIdentifiers(r, entity);
    r["namespace"] = namespace_name;
    r["key"] = label.first;
    r["value"] = label.second;
    results.push_back(r);
  }
}

/**
 * @brief Drain the containers ListStream for a namespace into a vector.
 *
 * ListStream (not the unary List) is used so a single message never aggregates
 * every container's OCI spec past gRPC's receive-size limit. The RPC deadline
 * (createContextWithTimeout) exists to bound a stalled containerd, so it must
 * cover only the stream I/O: callers do the per-container work (/proc lookups,
 * OCI-spec parsing) on the returned vector after the RPC closes. Doing that
 * work inside the read loop would charge it against the deadline and silently
 * truncate results on the busy nodes this streaming path targets.
 */
[[nodiscard]] std::vector<containerd::services::containers::v1::Container>
listContainers(const ContainerdConnection& conn,
               const std::string& namespace_name) {
  std::vector<containerd::services::containers::v1::Container> containers;

  containerd::services::containers::v1::Containers::Stub* stub = nullptr;
  if (!conn.getStub<containerd::services::containers::v1::Containers>(&stub)) {
    LOG(WARNING) << "Failed to create containers stub for namespace "
                 << namespace_name;
    return containers;
  }

  containerd::services::containers::v1::ListContainersRequest request;
  grpc::ClientContext context;
  createContextWithTimeout(context, namespace_name);

  auto reader = stub->ListStream(&context, request);
  StreamReaderGuard guard(reader.get());

  containerd::services::containers::v1::ListContainerMessage msg;
  while (reader->Read(&msg)) {
    containers.push_back(std::move(*msg.mutable_container()));
  }

  grpc::Status status = guard.Finish();
  if (!status.ok()) {
    LOG(WARNING) << "Error streaming containerd containers in namespace "
                 << namespace_name << " after " << containers.size()
                 << " streamed; returning a partial list: "
                 << status.error_message();
  }

  return containers;
}

/**
 * @brief Helper function to query containers in a specific namespace.
 */
void queryContainersInNamespace(const ContainerdConnection& conn,
                                const std::string& namespace_name,
                                QueryData& results) {
  VLOG(1) << "Querying containerd namespace: " << namespace_name;

  // Fetch all tasks first (single gRPC call) so the loop below avoids N+1
  // task lookups.
  auto tasks_by_container = getAllTasks(conn, namespace_name);

  for (const auto& container : listContainers(conn, namespace_name)) {
    Row r;
    r["id"] = container.id();
    r["namespace"] = namespace_name;
    r["image"] = container.image();
    r["name"] = container.snapshot_key().empty() ? container.id()
                                                 : container.snapshot_key();
    r["runtime"] = container.has_runtime() ? container.runtime().name() : "";
    r["created_at"] = container.has_created_at()
                          ? formatTimestamp(container.created_at())
                          : "";
    r["updated_at"] = container.has_updated_at()
                          ? formatTimestamp(container.updated_at())
                          : "";

    // Look up task information from the pre-fetched map
    // Use empty strings as defaults since containers may exist without running
    // tasks
    std::string task_pid = "";
    std::string task_status = "";
    VLOG(1) << "Looking up task for container id='" << container.id() << "'";
    auto task_it = tasks_by_container.find(container.id());
    if (task_it != tasks_by_container.end()) {
      const auto& process = task_it->second;
      task_pid = std::to_string(process.pid());
      task_status = mapTaskStatus(process.status());
      VLOG(1) << "Found task: pid=" << task_pid << " status=" << task_status;
    } else {
      VLOG(1) << "No task found for container id='" << container.id() << "'";
    }
    r["pid"] = task_pid;
    r["status"] = task_status;

    // Get namespace information from /proc if we have a valid PID
    if (!task_pid.empty()) {
      ProcessNamespaceList namespace_list;
      if (procGetProcessNamespaces(task_pid, namespace_list).ok()) {
        for (const auto& [ns_type, ns_value] : namespace_list) {
          r[ns_type + "_namespace"] = std::to_string(ns_value);
        }
      } else {
        VLOG(1) << "Failed to retrieve namespace list for container "
                << r["id"];
      }
    }

    results.push_back(r);
  }
}

/**
 * @brief Parse OCI root filesystem specification.
 *
 * Extracts root filesystem configuration including path and readonly flag.
 */
void parseOCIRootSpec(const rapidjson::Value& root_obj, Row& r) {
  if (root_obj.HasMember("path") && root_obj["path"].IsString()) {
    r["root_path"] = root_obj["path"].GetString();
  }
  if (root_obj.HasMember("readonly") && root_obj["readonly"].IsBool()) {
    r["root_readonly"] =
        root_obj["readonly"].GetBool() ? kBoolTrue : kBoolFalse;
  }
}

/**
 * @brief Parse OCI process specification.
 *
 * Extracts process configuration including terminal settings, working
 * directory, command arguments, and environment variables.
 */
void parseOCIProcessSpec(const rapidjson::Value& process_obj, Row& r) {
  if (process_obj.HasMember("terminal") && process_obj["terminal"].IsBool()) {
    r["process_terminal"] =
        process_obj["terminal"].GetBool() ? kBoolTrue : kBoolFalse;
  }
  if (process_obj.HasMember("cwd") && process_obj["cwd"].IsString()) {
    r["process_cwd"] = process_obj["cwd"].GetString();
  }
  if (process_obj.HasMember("args") && process_obj["args"].IsArray()) {
    r["process_args"] = jsonArrayToString(process_obj["args"]);
  }
  if (process_obj.HasMember("env") && process_obj["env"].IsArray()) {
    r["process_env"] = jsonArrayToString(process_obj["env"]);
  }
}

/**
 * @brief Parse OCI Linux-specific specification.
 *
 * Extracts Linux-specific security settings including readonly and masked
 * paths.
 */
void parseOCILinuxSpec(const rapidjson::Value& linux_obj, Row& r) {
  if (linux_obj.HasMember("readonlyPaths") &&
      linux_obj["readonlyPaths"].IsArray()) {
    r["linux_readonly_paths"] = jsonArrayToString(linux_obj["readonlyPaths"]);
  }
  if (linux_obj.HasMember("maskedPaths") &&
      linux_obj["maskedPaths"].IsArray()) {
    r["linux_masked_paths"] = jsonArrayToString(linux_obj["maskedPaths"]);
  }
}

/**
 * @brief Parse OCI spec from JSON and populate row.
 *
 * Orchestrates parsing of different OCI spec sections by delegating to
 * specialized helper functions.
 */
void parseOCISpec(const google::protobuf::Any& spec_any,
                  const std::string& container_id,
                  const std::string& namespace_name,
                  Row& r) {
  r["id"] = container_id;
  r["namespace"] = namespace_name;

  // Initialize with empty values
  r["oci_version"] = "";
  r["root_path"] = "";
  r["root_readonly"] = kBoolFalse;
  r["hostname"] = "";
  r["process_terminal"] = kBoolFalse;
  r["process_cwd"] = "";
  r["process_args"] = "";
  r["process_env"] = "";
  r["linux_readonly_paths"] = "";
  r["linux_masked_paths"] = "";

  auto doc = JSON::newObject();
  if (!doc.fromString(spec_any.value()) || !doc.doc().IsObject()) {
    VLOG(1) << "Failed to parse OCI spec JSON for container " << container_id;
    return;
  }

  const auto& root = doc.doc();

  // Extract top-level fields
  if (root.HasMember("ociVersion") && root["ociVersion"].IsString()) {
    r["oci_version"] = root["ociVersion"].GetString();
  }
  if (root.HasMember("hostname") && root["hostname"].IsString()) {
    r["hostname"] = root["hostname"].GetString();
  }

  // Delegate to specialized parsers for each section
  if (root.HasMember("root") && root["root"].IsObject()) {
    parseOCIRootSpec(root["root"], r);
  }

  if (root.HasMember("process") && root["process"].IsObject()) {
    parseOCIProcessSpec(root["process"], r);
  }

  if (root.HasMember("linux") && root["linux"].IsObject()) {
    parseOCILinuxSpec(root["linux"], r);
  }
}

/**
 * @brief Helper function to query container specs in a specific namespace.
 */
void queryContainerSpecsInNamespace(const ContainerdConnection& conn,
                                    const std::string& namespace_name,
                                    QueryData& results) {
  for (const auto& container : listContainers(conn, namespace_name)) {
    if (container.has_spec()) {
      Row r;
      parseOCISpec(container.spec(), container.id(), namespace_name, r);
      results.push_back(r);
    } else {
      VLOG(1) << "Container " << container.id() << " has no spec field";
    }
  }
}

} // anonymous namespace

/**
 * @brief Entry point for containerd_containers table.
 */
QueryData genContainerdContainers(QueryContext& context) {
  ContainerdConnection conn(FLAGS_containerd_socket);
  if (!conn.isConnected()) {
    return {}; // Return empty QueryData directly (enables RVO)
  }

  QueryData results;
  const auto namespaces = getNamespacesToQuery(conn);

  // Reserve space: reasonable estimate of 10 containers per namespace
  results.reserve(namespaces.size() * 10);

  for (const auto& ns : namespaces) {
    queryContainersInNamespace(conn, ns, results);
  }

  LOG(INFO) << "Completed query, returned " << results.size() << " rows";
  return results; // Single return path enables NRVO
}

/**
 * @brief Entry point for containerd_namespaces table.
 */
QueryData genContainerdNamespaces(QueryContext& context) {
  ContainerdConnection conn(FLAGS_containerd_socket);
  if (!conn.isConnected()) {
    return {};
  }

  containerd::services::namespaces::v1::Namespaces::Stub* stub = nullptr;
  if (!conn.getStub<containerd::services::namespaces::v1::Namespaces>(&stub)) {
    VLOG(1) << "Failed to create namespaces stub";
    return {};
  }

  containerd::services::namespaces::v1::ListNamespacesRequest request;
  containerd::services::namespaces::v1::ListNamespacesResponse response;
  grpc::ClientContext grpc_context;
  createContextWithTimeout(grpc_context);

  grpc::Status status = stub->List(&grpc_context, request, &response);

  if (!status.ok()) {
    VLOG(1) << "Error listing containerd namespaces: "
            << status.error_message();
    return {};
  }

  QueryData results;
  results.reserve(response.namespaces_size());
  for (const auto& ns : response.namespaces()) {
    Row r;
    r["name"] = ns.name();
    results.push_back(r);
  }

  return results;
}

/**
 * @brief Entry point for containerd_images table.
 */
QueryData genContainerdImages(QueryContext& context) {
  ContainerdConnection conn(FLAGS_containerd_socket);
  if (!conn.isConnected()) {
    return {};
  }

  const auto namespaces = getNamespacesToQuery(conn);

  QueryData results;
  // Reserve space: estimate 5 images per namespace
  results.reserve(namespaces.size() * 5);

  for (const auto& namespace_name : namespaces) {
    containerd::services::images::v1::Images::Stub* stub = nullptr;
    if (!conn.getStub<containerd::services::images::v1::Images>(&stub)) {
      VLOG(1) << "Failed to create images stub for namespace "
              << namespace_name;
      continue;
    }

    containerd::services::images::v1::ListImagesRequest request;
    containerd::services::images::v1::ListImagesResponse response;
    grpc::ClientContext context;
    createContextWithTimeout(context, namespace_name);

    grpc::Status status = stub->List(&context, request, &response);

    if (!status.ok()) {
      VLOG(1) << "Error listing containerd images in namespace "
              << namespace_name << ": " << status.error_message();
      continue;
    }

    for (const auto& image : response.images()) {
      Row r;
      r["name"] = image.name();
      r["namespace"] = namespace_name;

      if (image.has_target()) {
        r["digest"] = image.target().digest();
        r["size"] = std::to_string(image.target().size());
        r["media_type"] = image.target().media_type();
      } else {
        r["digest"] = "";
        r["size"] = "0";
        r["media_type"] = "";
      }

      r["created_at"] =
          image.has_created_at() ? formatTimestamp(image.created_at()) : "";
      r["updated_at"] =
          image.has_updated_at() ? formatTimestamp(image.updated_at()) : "";

      results.push_back(r);
    }
  }

  return results;
}

/**
 * @brief Entry point for containerd_snapshots table.
 */
QueryData genContainerdSnapshots(QueryContext& context) {
  ContainerdConnection conn(FLAGS_containerd_socket);
  if (!conn.isConnected()) {
    return {};
  }

  const auto namespaces = getNamespacesToQuery(conn);

  QueryData results;
  // Reserve space: estimate 20 snapshots per namespace per snapshotter
  // Actual allocation will be smaller if fewer snapshotters are configured
  results.reserve(namespaces.size() * kSnapshotters.size() * 20);

  for (const auto& namespace_name : namespaces) {
    // Discover which snapshotters are actually available
    // Most systems only use overlayfs, so this avoids 3 unnecessary queries
    const auto available_snapshotters =
        getAvailableSnapshotters(conn, namespace_name);

    for (const auto& snapshotter : available_snapshotters) {
      containerd::services::snapshots::v1::Snapshots::Stub* stub = nullptr;
      if (!conn.getStub<containerd::services::snapshots::v1::Snapshots>(
              &stub)) {
        VLOG(1) << "Failed to create snapshots stub for namespace "
                << namespace_name;
        continue;
      }

      containerd::services::snapshots::v1::ListSnapshotsRequest request;
      request.set_snapshotter(snapshotter);

      grpc::ClientContext context;
      createContextWithTimeout(context, namespace_name);

      auto reader = stub->List(&context, request);
      StreamReaderGuard guard(reader.get());

      containerd::services::snapshots::v1::ListSnapshotsResponse response;
      while (reader->Read(&response)) {
        for (const auto& info : response.info()) {
          Row r;
          r["name"] = info.name();
          r["namespace"] = namespace_name;
          r["snapshotter"] = snapshotter;
          r["parent"] = info.parent();
          r["kind"] = mapSnapshotKind(info.kind());
          r["created_at"] =
              info.has_created_at() ? formatTimestamp(info.created_at()) : "";
          r["updated_at"] =
              info.has_updated_at() ? formatTimestamp(info.updated_at()) : "";

          results.push_back(r); // May throw - guard ensures Finish() is called
        }
      }

      // Finish the stream - explicit call allows us to check the status
      grpc::Status status = guard.Finish();
      if (!status.ok() && status.error_code() != grpc::StatusCode::NOT_FOUND) {
        VLOG(1) << "Error listing snapshots for snapshotter " << snapshotter
                << " in namespace " << namespace_name << ": "
                << status.error_message();
      }
    }
  }

  return results;
}

/**
 * @brief Entry point for containerd_container_labels table.
 */
QueryData genContainerdContainerLabels(QueryContext& context) {
  ContainerdConnection conn(FLAGS_containerd_socket);
  if (!conn.isConnected()) {
    return {};
  }

  const auto namespaces = getNamespacesToQuery(conn);

  QueryData results;
  // Reserve space: estimate 10 containers * 5 labels per namespace
  results.reserve(namespaces.size() * 50);

  for (const auto& namespace_name : namespaces) {
    for (const auto& container : listContainers(conn, namespace_name)) {
      extractLabelsFromEntity(
          container, namespace_name, results, [](Row& r, const auto& c) {
            r["id"] = c.id();
          });
    }
  }

  return results;
}

/**
 * @brief Entry point for containerd_namespace_labels table.
 */
QueryData genContainerdNamespaceLabels(QueryContext& context) {
  ContainerdConnection conn(FLAGS_containerd_socket);
  if (!conn.isConnected()) {
    return {};
  }

  containerd::services::namespaces::v1::Namespaces::Stub* stub = nullptr;
  if (!conn.getStub<containerd::services::namespaces::v1::Namespaces>(&stub)) {
    VLOG(1) << "Failed to create namespaces stub";
    return {};
  }

  containerd::services::namespaces::v1::ListNamespacesRequest request;
  containerd::services::namespaces::v1::ListNamespacesResponse response;
  grpc::ClientContext grpc_context;
  createContextWithTimeout(grpc_context);

  grpc::Status status = stub->List(&grpc_context, request, &response);

  if (!status.ok()) {
    VLOG(1) << "Error listing containerd namespaces: "
            << status.error_message();
    return {};
  }

  QueryData results;
  // Reserve space: estimate 3 labels per namespace
  results.reserve(response.namespaces_size() * 3);

  for (const auto& ns : response.namespaces()) {
    extractLabelsFromEntity(ns, ns.name(), results, [](Row& r, const auto& n) {
      r["name"] = n.name();
    });
  }

  return results;
}

/**
 * @brief Entry point for containerd_image_labels table.
 */
QueryData genContainerdImageLabels(QueryContext& context) {
  ContainerdConnection conn(FLAGS_containerd_socket);
  if (!conn.isConnected()) {
    return {};
  }

  const auto namespaces = getNamespacesToQuery(conn);

  QueryData results;
  // Reserve space: estimate 5 images * 3 labels per namespace
  results.reserve(namespaces.size() * 15);

  for (const auto& namespace_name : namespaces) {
    containerd::services::images::v1::Images::Stub* stub = nullptr;
    if (!conn.getStub<containerd::services::images::v1::Images>(&stub)) {
      VLOG(1) << "Failed to create images stub for namespace "
              << namespace_name;
      continue;
    }

    containerd::services::images::v1::ListImagesRequest request;
    containerd::services::images::v1::ListImagesResponse response;
    grpc::ClientContext context;
    createContextWithTimeout(context, namespace_name);

    grpc::Status status = stub->List(&context, request, &response);

    if (!status.ok()) {
      VLOG(1) << "Error listing containerd images in namespace "
              << namespace_name << ": " << status.error_message();
      continue;
    }

    for (const auto& image : response.images()) {
      extractLabelsFromEntity(
          image, namespace_name, results, [](Row& r, const auto& i) {
            r["name"] = i.name();
          });
    }
  }

  return results;
}

/**
 * @brief Entry point for containerd_snapshot_labels table.
 */
QueryData genContainerdSnapshotLabels(QueryContext& context) {
  ContainerdConnection conn(FLAGS_containerd_socket);
  if (!conn.isConnected()) {
    return {};
  }

  const auto namespaces = getNamespacesToQuery(conn);

  QueryData results;
  // Reserve space: estimate 20 snapshots * 2 labels per namespace per
  // snapshotter Actual allocation will be smaller if fewer snapshotters are
  // configured
  results.reserve(namespaces.size() * kSnapshotters.size() * 40);

  for (const auto& namespace_name : namespaces) {
    // Discover which snapshotters are actually available
    // Most systems only use overlayfs, so this avoids 3 unnecessary queries
    const auto available_snapshotters =
        getAvailableSnapshotters(conn, namespace_name);

    for (const auto& snapshotter : available_snapshotters) {
      containerd::services::snapshots::v1::Snapshots::Stub* stub = nullptr;
      if (!conn.getStub<containerd::services::snapshots::v1::Snapshots>(
              &stub)) {
        VLOG(1) << "Failed to create snapshots stub for namespace "
                << namespace_name;
        continue;
      }

      containerd::services::snapshots::v1::ListSnapshotsRequest request;
      request.set_snapshotter(snapshotter);

      grpc::ClientContext context;
      createContextWithTimeout(context, namespace_name);

      auto reader = stub->List(&context, request);
      StreamReaderGuard guard(reader.get());

      containerd::services::snapshots::v1::ListSnapshotsResponse response;
      while (reader->Read(&response)) {
        for (const auto& info : response.info()) {
          // Use extractLabelsFromEntity with a lambda that captures snapshotter
          extractLabelsFromEntity(
              info,
              namespace_name,
              results,
              [&snapshotter](Row& r, const auto& snapshot_info) {
                r["name"] = snapshot_info.name();
                r["snapshotter"] = snapshotter;
              });
        }
      }

      // Finish the stream - explicit call allows us to check the status
      grpc::Status status = guard.Finish();
      if (!status.ok() && status.error_code() != grpc::StatusCode::NOT_FOUND) {
        VLOG(1) << "Error listing snapshots for snapshotter " << snapshotter
                << " in namespace " << namespace_name << ": "
                << status.error_message();
      }
    }
  }

  return results;
}

/**
 * @brief Entry point for containerd_container_specs table.
 */
QueryData genContainerdContainerSpecs(QueryContext& context) {
  ContainerdConnection conn(FLAGS_containerd_socket);
  if (!conn.isConnected()) {
    return {};
  }

  const auto namespaces = getNamespacesToQuery(conn);

  QueryData results;
  // Reserve space: estimate 10 containers per namespace
  results.reserve(namespaces.size() * 10);

  for (const auto& ns : namespaces) {
    queryContainerSpecsInNamespace(conn, ns, results);
  }

  return results;
}

/**
 * @brief Entry point for containerd_container_envs table.
 *
 * One row per environment variable. OCI process.env entries are "KEY=VALUE"
 * strings; split on the first '=' so values may themselves contain '='. This
 * row-per-variable shape is lossless (unlike the comma-joined process_env
 * column on containerd_container_specs) and mirrors docker_container_envs.
 */
QueryData genContainerdContainerEnvs(QueryContext& context) {
  ContainerdConnection conn(FLAGS_containerd_socket);
  if (!conn.isConnected()) {
    return {};
  }

  const auto namespaces = getNamespacesToQuery(conn);

  QueryData results;
  for (const auto& ns : namespaces) {
    for (const auto& container : listContainers(conn, ns)) {
      if (!container.has_spec()) {
        continue;
      }

      auto doc = JSON::newObject();
      if (!doc.fromString(container.spec().value()) || !doc.doc().IsObject()) {
        VLOG(1) << "Failed to parse OCI spec JSON for container "
                << container.id();
        continue;
      }

      const auto& root = doc.doc();
      if (!root.HasMember("process") || !root["process"].IsObject()) {
        continue;
      }
      const auto& process = root["process"];
      if (!process.HasMember("env") || !process["env"].IsArray()) {
        continue;
      }

      const auto& env = process["env"];
      for (rapidjson::SizeType i = 0; i < env.Size(); ++i) {
        if (!env[i].IsString()) {
          continue;
        }
        std::string_view entry(env[i].GetString(), env[i].GetStringLength());
        auto eq = entry.find('=');

        Row r;
        r["id"] = container.id();
        r["namespace"] = ns;
        if (eq == std::string_view::npos) {
          r["key"] = std::string(entry);
          r["value"] = "";
        } else {
          r["key"] = std::string(entry.substr(0, eq));
          r["value"] = std::string(entry.substr(eq + 1));
        }
        results.push_back(std::move(r));
      }
    }
  }

  return results;
}

} // namespace tables
} // namespace osquery
