/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/events/linux/bpfprocesseventspublisher.h>
#include <osquery/events/linux/setrlimit.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

namespace osquery {
namespace {
const std::size_t kEventMapSize{2048U};
const std::size_t kBufferStorageEntrySize{4096};
const std::size_t kBufferStorageEntryCount{2048};
const std::size_t kPerfEventArraySizeExponent{13U};

const std::vector<std::string> kSyscallNameList = {"execve", "execveat"};

using FunctionTracerArgv = tob::ebpfpub::IFunctionTracer::Event::Field::Argv;
} // namespace

FLAG(bool,
     enable_bpf_process_events,
     false,
     "Enables the bpf_process_events publisher");

REGISTER(BPFProcessEventsPublisher,
         "event_publisher",
         "BPFProcessEventsPublisher");

struct BPFProcessEventsPublisher::PrivateData final {
  bool initialized{false};

  tob::ebpfpub::IBufferStorage::Ref buffer_storage;
  tob::ebpf::PerfEventArray::Ref perf_event_array;
  tob::ebpfpub::IPerfEventReader::Ref perf_event_reader;

  std::uint64_t execve_tracepoint_id{0U};
  std::uint64_t execveat_tracepoint_id{0U};
};

Status BPFProcessEventsPublisher::setUp() {
  if (!FLAGS_enable_bpf_process_events) {
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

    auto function_tracer = function_tracer_exp.takeValue();
    perf_event_reader->insert(std::move(function_tracer));
  }

  d->buffer_storage = std::move(buffer_storage);
  d->perf_event_array = std::move(perf_event_array);
  d->perf_event_reader = std::move(perf_event_reader);

  d->initialized = true;
  return Status::success();
}

void BPFProcessEventsPublisher::configure() {
  if (!FLAGS_enable_bpf_process_events) {
    return;
  }
}

void BPFProcessEventsPublisher::tearDown() {
  if (!FLAGS_enable_bpf_process_events) {
    return;
  }

  if (!d->initialized) {
    return;
  }
}

Status BPFProcessEventsPublisher::run() {
  if (!FLAGS_enable_bpf_process_events) {
    return Status::failure("Publisher disabled via configuration");
  }

  if (!d->initialized) {
    return Status::failure(
        "Halting the publisher since initialization has failed");
  }

  auto callback = std::bind(&BPFProcessEventsPublisher::eventCallback,
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

BPFProcessEventsPublisher::BPFProcessEventsPublisher() : d(new PrivateData) {}

BPFProcessEventsPublisher::~BPFProcessEventsPublisher() {
  tearDown();
}

void BPFProcessEventsPublisher::eventCallback(
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
    BPFProcessEventsEC::Event event = {};

    event.timestamp = bpf_event.header.timestamp;
    event.thread_id = bpf_event.header.thread_id;
    event.process_id = bpf_event.header.process_id;
    event.user_id = bpf_event.header.user_id;
    event.group_id = bpf_event.header.group_id;
    event.cgroup_id = bpf_event.header.cgroup_id;
    event.exit_code = bpf_event.header.exit_code;
    event.probe_error = bpf_event.header.probe_error;
    event.syscall_name = bpf_event.name;

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

    event.binary_path = std::get<std::string>(filename_field.data_var);

    field_it = bpf_event.in_field_map.find("argv");
    if (field_it == bpf_event.in_field_map.end()) {
      LOG(ERROR) << "Missing argv parameter in exec event";

    } else {
      const auto& argv_field = field_it->second;

      if (!std::holds_alternative<FunctionTracerArgv>(argv_field.data_var)) {
        LOG(ERROR) << "Invalid argv parameter in exec event";

      } else {
        event.argument_list = std::get<FunctionTracerArgv>(argv_field.data_var);
      }
    }

    event_context->event_list.push_back(std::move(event));
  }

  if (event_context->event_list.empty()) {
    return;
  }

  fire(event_context);
}
} // namespace osquery
