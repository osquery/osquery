/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <iomanip>
#include <sstream>

#include <osquery/events/linux/bpfsocketeventspublisher.h>
#include <osquery/events/linux/setrlimit.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

#include <linux/netlink.h>
#include <netinet/in.h>
#include <sys/un.h>

namespace osquery {
namespace {
const std::vector<std::string> kSyscallNameList = {
    "connect", "bind", "accept", "accept4"};

const std::size_t kEventMapSize{2048U};
const std::size_t kBufferStorageEntrySize{1024};
const std::size_t kBufferStorageEntryCount{4096};
const std::size_t kPerfEventArraySizeExponent{13U};

// We'll use these two parameter lists to trace execve/execveat without
// capturing the argv map. We don't need the cmdline here and it's good
// to skip it to save memory

// clang-format off
tob::ebpfpub::IFunctionTracer::ParameterList kExecveParameterList = {
  {
    "filename",
    tob::ebpfpub::IFunctionTracer::Parameter::Type::String,
    tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
    {}
  },

  {
    "argv",
    tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
    tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
    8U
  },

  {
    "envp",
    tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
    tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
    8U
  }
};
// clang-format on

// clang-format off
tob::ebpfpub::IFunctionTracer::ParameterList kExecveAtParameterList = {
  {
    "fd",
    tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
    tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
    8U
  },

  {
    "filename",
    tob::ebpfpub::IFunctionTracer::Parameter::Type::String,
    tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
    {}
  },

  {
    "argv",
    tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
    tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
    8U
  },

  {
    "envp",
    tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
    tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
    8U
  },

  {
    "flags",
    tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
    tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
    8U
  }
};
// clang-format on

Status parseSockaddrBuffer(std::string& address_family,
                           std::string& address,
                           std::uint16_t& port,
                           FunctionTracerBuffer& buffer) {
  address_family = {};
  address = {};
  port = 0U;

  if (buffer.size() < sizeof(sa_family_t)) {
    return Status::failure("Invalid sockaddr buffer");
  }

  sa_family_t sa_family{0U};
  std::memcpy(&sa_family, buffer.data(), sizeof(sa_family));

  if (sa_family == AF_UNSPEC) {
    // We could also trace socket() to make sure we correctly handle AF_UNSPEC
    sa_family = AF_INET;
  }

  if (sa_family == AF_INET) {
    address_family = "AF_INET";

    if (buffer.size() < sizeof(sockaddr_in)) {
      return Status::failure("Invalid sockaddr_in buffer");
    }

    struct sockaddr_in sockaddr = {};
    std::memcpy(&sockaddr, buffer.data(), sizeof(sockaddr));

    std::uint8_t address_parts[4U] = {};
    std::memcpy(
        address_parts, &sockaddr.sin_addr.s_addr, sizeof(address_parts));

    address = std::to_string(address_parts[0]) + "." +
              std::to_string(address_parts[1]) + "." +
              std::to_string(address_parts[2]) + "." +
              std::to_string(address_parts[3]);

    port = htons(sockaddr.sin_port);

  } else if (sa_family == AF_UNIX) {
    address_family = "AF_UNIX";

    if (buffer.size() < 2 || buffer.size() > sizeof(sockaddr_un)) {
      return Status::failure("Invalid sockaddr_un buffer");
    }

    auto size = std::min(buffer.size(), sizeof(sockaddr_un));

    struct sockaddr_un sockaddr = {};
    std::memcpy(&sockaddr, buffer.data(), size);

    address.assign(sockaddr.sun_path, 108);
    port = 0U;

  } else if (sa_family == AF_INET6) {
    address_family = "AF_INET6";

    if (buffer.size() < sizeof(sockaddr_in6)) {
      return Status::failure("Invalid sockaddr_in6 buffer");
    }

    struct sockaddr_in6 sockaddr = {};
    std::memcpy(&sockaddr, buffer.data(), sizeof(sockaddr));

    std::stringstream addr_stream;
    for (auto i = 0; i < 16; ++i) {
      addr_stream << std::hex << std::setfill('0') << std::setw(2)
                  << static_cast<int>(sockaddr.sin6_addr.s6_addr[i]);

      if (i != 15) {
        addr_stream << ":";
      }
    }

    address = addr_stream.str();
    port = htons(sockaddr.sin6_port);

  } else if (sa_family == AF_NETLINK) {
    address_family = "AF_NETLINK";

    if (buffer.size() < sizeof(sockaddr_nl)) {
      return Status::failure("Invalid sockaddr_nl buffer");
    }

    struct sockaddr_nl sockaddr = {};
    std::memcpy(&sockaddr, buffer.data(), sizeof(sockaddr));

    address = std::to_string(sockaddr.nl_pid);
    port = 0;

  } else {
    return Status::failure("Unsupported sockaddr type. sa_family: " +
                           std::to_string(sa_family));
  }

  return Status::success();
}
} // namespace

FLAG(bool,
     enable_bpf_socket_events,
     false,
     "Enables the bpf_socket_events publisher");

REGISTER(BPFSocketEventsPublisher,
         "event_publisher",
         "BPFSocketEventsPublisher");

struct BPFSocketEventsPublisher::PrivateData final {
  bool initialized{false};

  tob::ebpfpub::IBufferStorage::Ref buffer_storage;
  tob::ebpf::PerfEventArray::Ref perf_event_array;
  tob::ebpfpub::IPerfEventReader::Ref perf_event_reader;

  std::unordered_map<pid_t, std::string> process_map;

  std::uint64_t connect_event_id{};
  std::uint64_t bind_event_id{};
  std::uint64_t accept_event_id{};
  std::uint64_t accept4_event_id{};

  std::uint64_t execve_event_id{};
  std::uint64_t execveat_event_id{};
};

Status BPFSocketEventsPublisher::setUp() {
  if (!FLAGS_enable_bpf_socket_events) {
    return Status::failure("Publisher disabled via configuration");
  }

  auto status = configureBPFMemoryLimits();
  if (!status.ok()) {
    return status;
  }

  auto buffer_storage_exp = tob::ebpfpub::IBufferStorage::create(
      kBufferStorageEntrySize, kBufferStorageEntryCount);

  if (!buffer_storage_exp.succeeded()) {
    return Status::failure("Failed to create the buffer storage: " +
                           buffer_storage_exp.error().message());
  }

  auto buffer_storage = buffer_storage_exp.takeValue();

  auto perf_event_array_exp =
      tob::ebpf::PerfEventArray::create(kPerfEventArraySizeExponent);

  if (!perf_event_array_exp.succeeded()) {
    return Status::failure("Failed to create the perf event array: " +
                           perf_event_array_exp.error().message());
  }

  auto perf_event_array = perf_event_array_exp.takeValue();

  auto perf_event_reader_exp =
      tob::ebpfpub::IPerfEventReader::create(*perf_event_array.get());

  if (!perf_event_reader_exp.succeeded()) {
    return Status::failure("Failed to create the perf event reader: " +
                           perf_event_reader_exp.error().message());
  }

  auto perf_event_reader = perf_event_reader_exp.takeValue();

  for (const auto& syscall_name : kSyscallNameList) {
    auto function_tracer_exp =
        tob::ebpfpub::IFunctionTracer::createFromSyscallTracepoint(
            syscall_name,
            *buffer_storage.get(),
            *perf_event_array.get(),
            kEventMapSize);

    if (!function_tracer_exp.succeeded()) {
      return Status::failure("Failed to create the function tracer: " +
                             function_tracer_exp.error().message());
    }

    std::uint64_t* event_identifier = nullptr;
    if (syscall_name == "connect") {
      event_identifier = &d->connect_event_id;

    } else if (syscall_name == "bind") {
      event_identifier = &d->bind_event_id;

    } else if (syscall_name == "accept") {
      event_identifier = &d->accept_event_id;

    } else if (syscall_name == "accept4") {
      event_identifier = &d->accept4_event_id;
    }

    auto function_tracer = function_tracer_exp.takeValue();
    *event_identifier = function_tracer->eventIdentifier();

    perf_event_reader->insert(std::move(function_tracer));
  }

  auto function_tracer_exp =
      tob::ebpfpub::IFunctionTracer::createFromSyscallTracepoint(
          "execve",
          kExecveParameterList,
          *buffer_storage.get(),
          *perf_event_array.get(),
          kEventMapSize);

  if (!function_tracer_exp.succeeded()) {
    return Status::failure("Failed to create the function tracer: " +
                           function_tracer_exp.error().message());
  }

  auto function_tracer = function_tracer_exp.takeValue();
  d->execve_event_id = function_tracer->eventIdentifier();
  perf_event_reader->insert(std::move(function_tracer));

  function_tracer_exp =
      tob::ebpfpub::IFunctionTracer::createFromSyscallTracepoint(
          "execveat",
          kExecveAtParameterList,
          *buffer_storage.get(),
          *perf_event_array.get(),
          kEventMapSize);

  if (!function_tracer_exp.succeeded()) {
    return Status::failure("Failed to create the function tracer: " +
                           function_tracer_exp.error().message());
  }

  function_tracer = function_tracer_exp.takeValue();
  d->execveat_event_id = function_tracer->eventIdentifier();
  perf_event_reader->insert(std::move(function_tracer));

  d->buffer_storage = std::move(buffer_storage);
  d->perf_event_array = std::move(perf_event_array);
  d->perf_event_reader = std::move(perf_event_reader);

  d->initialized = true;
  return Status::success();
}

void BPFSocketEventsPublisher::configure() {
  if (!FLAGS_enable_bpf_socket_events) {
    return;
  }
}

void BPFSocketEventsPublisher::tearDown() {
  if (!FLAGS_enable_bpf_socket_events) {
    return;
  }

  if (!d->initialized) {
    return;
  }
}

Status BPFSocketEventsPublisher::run() {
  if (!FLAGS_enable_bpf_socket_events) {
    return Status::failure("Publisher disabled via configuration");
  }

  auto callback = std::bind(&BPFSocketEventsPublisher::eventCallback,
                            this,
                            std::placeholders::_1,
                            std::placeholders::_2);

  while (!isEnding()) {
    auto success_exp =
        d->perf_event_reader->exec(std::chrono::seconds(1U), callback);

    if (success_exp.failed()) {
      LOG(ERROR) << success_exp.error().message();
    }
  }

  return Status::success();
}

BPFSocketEventsPublisher::BPFSocketEventsPublisher() : d(new PrivateData) {}

BPFSocketEventsPublisher::~BPFSocketEventsPublisher() {
  tearDown();
}

void BPFSocketEventsPublisher::eventCallback(
    const tob::ebpfpub::IFunctionTracer::EventList& bpf_event_list,
    const tob::ebpfpub::IPerfEventReader::ErrorCounters& error_counters) {
  if (error_counters.invalid_probe_output > 0U) {
    LOG(ERROR) << "Invalid probe output encountered ("
               << error_counters.invalid_probe_output << " times)";
  }

  if (error_counters.lost_events > 0U) {
    LOG(ERROR) << "Lost " << error_counters.lost_events << " events";
  }

  if (bpf_event_list.empty()) {
    return;
  }

  auto event_context = createEventContext();

  for (const auto& bpf_event : bpf_event_list) {
    if (bpf_event.identifier == d->execve_event_id ||
        bpf_event.identifier == d->execveat_event_id) {
      auto field_it = bpf_event.in_field_map.find("filename");
      if (field_it == bpf_event.in_field_map.end()) {
        LOG(ERROR) << "Missing filename parameter in exec event";
        continue;
      }

      const auto& filename_field = field_it->second;
      if (!std::holds_alternative<std::string>(filename_field.data_var)) {
        LOG(ERROR) << "Invalid filename parameter in exec event";
        continue;
      }

      auto binary_path = std::get<std::string>(filename_field.data_var);
      d->process_map[bpf_event.header.process_id] = std::move(binary_path);

      continue;
    }

    BPFSocketEventsEC::Event event = {};
    event.timestamp = bpf_event.header.timestamp;
    event.thread_id = bpf_event.header.thread_id;
    event.process_id = bpf_event.header.process_id;
    event.user_id = bpf_event.header.user_id;
    event.group_id = bpf_event.header.group_id;
    event.cgroup_id = bpf_event.header.cgroup_id;
    event.exit_code = bpf_event.header.exit_code;
    event.probe_error = bpf_event.header.probe_error;
    event.syscall_name = bpf_event.name;
    event.binary_path = d->process_map[bpf_event.header.process_id];

    bool local_address{false};
    if (bpf_event.identifier == d->accept_event_id ||
        bpf_event.identifier == d->accept4_event_id) {
      local_address = false;

    } else if (bpf_event.identifier == d->connect_event_id) {
      local_address = false;

    } else if (bpf_event.identifier == d->bind_event_id) {
      local_address = true;

    } else {
      LOG(ERROR) << "Unexpected syscall type";
      continue;
    }

    FunctionTracerBuffer address_buffer;
    auto status = getSocketEventAddress(address_buffer, bpf_event);
    if (!status.ok()) {
      LOG(ERROR) << status.getMessage();
      continue;
    }

    std::string address_family = {};
    std::string address = {};
    std::uint16_t port = {};

    status = parseSockaddrBuffer(address_family, address, port, address_buffer);

    if (!status.ok()) {
      LOG(ERROR) << status.getMessage();
      continue;
    }

    event.address_family = address_family;

    if (local_address) {
      event.local_address = address;
      event.local_port = port;

    } else {
      event.remote_address = address;
      event.remote_port = port;
    }

    event_context->event_list.push_back(std::move(event));
  }

  fire(event_context);
}

Status BPFSocketEventsPublisher::getSocketEventAddress(
    FunctionTracerBuffer& buffer,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  buffer = {};

  if (event.identifier == d->accept_event_id ||
      event.identifier == d->accept4_event_id) {
    auto field_it = event.out_field_map.find("upeer_sockaddr");
    if (field_it == event.out_field_map.end()) {
      return Status::failure(
          "Missing upeer_sockaddr OUT field in accept/accept4 event");
    }

    const auto& field = field_it->second;
    if (!std::holds_alternative<FunctionTracerBuffer>(field.data_var)) {
      return Status::failure(
          "Invalid upeer_sockaddr OUT field in accept/accept4 event");
    }

    buffer = std::get<FunctionTracerBuffer>(field.data_var);
    return Status::success();
  }

  const char* field_name{nullptr};
  if (event.identifier == d->connect_event_id) {
    field_name = "uservaddr";

  } else if (event.identifier == d->bind_event_id) {
    field_name = "umyaddr";

  } else {
    return Status::failure("Invalid event socket event type");
  }

  auto field_it = event.in_field_map.find(field_name);
  if (field_it == event.in_field_map.end()) {
    auto error_message = std::string("Missing ") + field_name +
                         " IN field in connect/bind event";
    return Status::failure(error_message);
  }

  const auto& field = field_it->second;
  if (!std::holds_alternative<FunctionTracerBuffer>(field.data_var)) {
    auto error_message = std::string("Invalid ") + field_name +
                         " IN field in connect/bind event";
    return Status::failure(error_message);
  }

  buffer = std::get<FunctionTracerBuffer>(field.data_var);
  return Status::success();
}
} // namespace osquery
