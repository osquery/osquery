/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <condition_variable>
#include <future>
#include <iostream>
#include <mutex>

#include <osquery/events/linux/bpfprocesseventspublisher.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/utils/conversions/tryto.h>

#include <ebpfpub/ifunctiontracer.h>
#include <ebpfpub/iperfeventreader.h>

#include <sys/resource.h>

namespace osquery {
FLAG(bool,
     enable_bpf_process_events,
     false,
     "Enables the bpf_process_events publisher");

REGISTER(BPFProcessEventsPublisher,
         "event_publisher",
         "BPFProcessEventsPublisher");

namespace {
const std::vector<std::string> kSyscallNameList{"execve", "execveat"};
const std::size_t kEventMapSize{1024};

Status setMemlockLimit() {
  struct rlimit rl = {};
  rl.rlim_max = RLIM_INFINITY;
  rl.rlim_cur = rl.rlim_max;

  auto err = setrlimit(RLIMIT_MEMLOCK, &rl);
  if (err != 0) {
    return Status::failure("Failed to setup the memory lock limits");
  }

  return Status::success();
}

void printEventHeader(
    const tob::ebpfpub::IFunctionSerializer::Event::Header& header) {
  std::cout << "timestamp: " << header.timestamp << " ";

  std::cout << "process_id: " << header.process_id << " ";
  std::cout << "thread_id: " << header.thread_id << " ";

  std::cout << "user_id: " << header.user_id << " ";
  std::cout << "group_id: " << header.group_id << " ";

  std::cout << "exit_code: " << header.exit_code << " ";
  std::cout << "probe_error: " << header.probe_error << "\n";
}

void printEventOptionalVariant(
    const tob::ebpfpub::IFunctionSerializer::Event::OptionalVariant&
        opt_variant) {
  if (!opt_variant.has_value()) {
    std::cout << "<NULL>";
    return;
  }

  auto variant = opt_variant.value();

  if (std::holds_alternative<std::string>(variant)) {
    const auto& value = std::get<std::string>(variant);
    std::cout << "'" << value << "'";

  } else if (std::holds_alternative<std::vector<std::uint8_t>>(variant)) {
    const auto& value = std::get<std::vector<std::uint8_t>>(variant);

    std::cout << "<buffer of " << value.size() << " bytes";

  } else if (std::holds_alternative<
                 tob::ebpfpub::IFunctionSerializer::Event::Integer>(variant)) {
    const auto& integer =
        std::get<tob::ebpfpub::IFunctionSerializer::Event::Integer>(variant);

    if (integer.is_signed) {
      std::cout << static_cast<int>(integer.value);
    } else {
      std::cout << static_cast<std::uint64_t>(integer.value);
    }

  } else {
    std::cout << "<ERROR>";
  }
}

void printEvent(const tob::ebpfpub::IFunctionSerializer::Event& event) {
  printEventHeader(event.header);

  std::cout << "syscall: " << event.name << " ";

  for (const auto& field : event.field_map) {
    const auto& field_name = field.first;
    const auto& field_opt_variant = field.second;

    std::cout << field_name << ": ";
    printEventOptionalVariant(field_opt_variant);

    std::cout << " ";
  }

  std::cout << "\n\n";
}
} // namespace

struct BPFProcessEventsPublisher::PrivateData final {
  std::atomic_bool terminate{false};
  std::future<tob::SuccessOrStringError> perf_event_reader_error;

  tob::ebpfpub::IFunctionSerializer::EventList event_list;
  std::mutex event_list_mutex;
  std::condition_variable event_list_cv;

  tob::ebpfpub::IBufferStorage::Ref buffer_storage;
  tob::ebpf::PerfEventArray::Ref perf_event_array;
  tob::ebpfpub::IPerfEventReader::Ref perf_event_reader;

  std::vector<tob::ebpfpub::IFunctionTracer::Ref> function_tracer_list;
  bool initialized{false};
};

Status BPFProcessEventsPublisher::setUp() {
  if (!FLAGS_enable_bpf_process_events) {
    return Status::failure("Publisher disabled via configuration");
  }

  auto status = setMemlockLimit();
  if (!status.ok()) {
    return status;
  }

  auto buffer_storage_exp = tob::ebpfpub::IBufferStorage::create(4096U, 1024U);
  if (!buffer_storage_exp.succeeded()) {
    return Status::failure("Failed to create the buffer storage");
  }

  d->buffer_storage = buffer_storage_exp.takeValue();

  auto perf_event_array_exp = tob::ebpf::PerfEventArray::create(11U);

  if (!perf_event_array_exp.succeeded()) {
    return Status::failure("Failed to create the perf event array");
  }

  d->perf_event_array = perf_event_array_exp.takeValue();

  auto perf_event_reader_exp = tob::ebpfpub::IPerfEventReader::create(
      *d->perf_event_array.get(), *d->buffer_storage.get());

  if (!perf_event_reader_exp.succeeded()) {
    return Status::failure("Failed to create the perf event reader");
  }

  d->perf_event_reader = perf_event_reader_exp.takeValue();

  auto& buffer_storage_ref = *d->buffer_storage.get();
  auto& perf_event_array_ref = *d->perf_event_array.get();

  for (const auto& syscall_name : kSyscallNameList) {
    auto function_tracer_exp =
        tob::ebpfpub::IFunctionTracer::createFromSyscallTracepoint(
            syscall_name,
            buffer_storage_ref,
            perf_event_array_ref,
            kEventMapSize);

    if (!function_tracer_exp.succeeded()) {
      const auto& error = function_tracer_exp.error();
      return Status::failure(error.message());
    }

    auto function_tracer = function_tracer_exp.takeValue();
    d->perf_event_reader->insert(std::move(function_tracer));
  }

  d->terminate = false;

  // clang-format off
  d->perf_event_reader_error = std::async(
    std::launch::async,
    &tob::ebpfpub::IPerfEventReader::exec,
    d->perf_event_reader.get(),
    std::ref(d->terminate),

    [&](const tob::ebpfpub::IFunctionSerializer::EventList &event_list) -> void {
      eventCallback(event_list);
    }
  );
  // clang-format on

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

  auto success_exp = d->perf_event_reader_error.get();
  if (success_exp.failed()) {
    const auto& error = success_exp.error();
    LOG(ERROR) << "The perf event reader has returned an error: "
               << error.message();
  }

  d->function_tracer_list.clear();

  d->buffer_storage.reset();
  d->perf_event_array.reset();
  d->perf_event_reader.reset();
}

Status BPFProcessEventsPublisher::run() {
  if (!FLAGS_enable_bpf_process_events) {
    return Status::failure("Publisher disabled via configuration");
  }

  while (!(d->terminate = interrupted())) {
    tob::ebpfpub::IFunctionSerializer::EventList event_list = {};

    {
      std::unique_lock<std::mutex> lock(d->event_list_mutex);

      auto cv_status =
          d->event_list_cv.wait_for(lock, std::chrono::seconds(1U));

      if (cv_status == std::cv_status::no_timeout) {
        event_list = std::move(d->event_list);
        d->event_list = {};
      }
    }

    if (event_list.empty()) {
      continue;
    }

    auto syscall_event_list = generateSyscallEventList(event_list);
    if (syscall_event_list.empty()) {
      continue;
    }

    auto event_context = createEventContext();
    event_context->event_list = std::move(syscall_event_list);
    fire(event_context);
  }

  return Status::success();
}

BPFProcessEventsPublisher::BPFProcessEventsPublisher() : d(new PrivateData) {}

BPFProcessEventsPublisher::~BPFProcessEventsPublisher() {
  tearDown();
}

void BPFProcessEventsPublisher::eventCallback(
    const tob::ebpfpub::IFunctionSerializer::EventList& event_list) {
  std::lock_guard<std::mutex> lock(d->event_list_mutex);

  d->event_list.insert(d->event_list.end(),
                       std::make_move_iterator(event_list.begin()),
                       std::make_move_iterator(event_list.end()));

  d->event_list_cv.notify_all();
}

BPFProcessEventsEC::SyscallEventList
BPFProcessEventsPublisher::generateSyscallEventList(
    const tob::ebpfpub::IFunctionSerializer::EventList& event_list) {
  BPFProcessEventsEC::SyscallEventList syscall_event_list;

  for (const auto& event : event_list) {
    BPFProcessEventsEC::SyscallEvent new_event = {};
    new_event.syscall_name = event.name;
    new_event.timestamp = event.header.timestamp;

    new_event.process_id = event.header.process_id;
    new_event.thread_id = event.header.thread_id;

    new_event.user_id = event.header.user_id;
    new_event.group_id = event.header.group_id;

    new_event.exit_code = event.header.exit_code;
    new_event.probe_error = event.header.probe_error != 0;

    auto opt_var_it = event.field_map.find("argv");
    if (opt_var_it == event.field_map.end()) {
      LOG(ERROR)
          << "Failed to acquire the argv parameter from the syscall event";
      continue;
    }

    const auto& opt_var_argv = opt_var_it->second;
    std::string argv = {};
    if (opt_var_argv.has_value()) {
      const auto& variant = opt_var_argv.value();
      if (std::holds_alternative<std::string>(variant)) {
        argv = std::get<std::string>(variant);
      }
    }

    new_event.cmdline = std::move(argv);

    opt_var_it = event.field_map.find("pathname");
    if (opt_var_it == event.field_map.end()) {
      opt_var_it = event.field_map.find("filename");
    }

    if (opt_var_it == event.field_map.end()) {
      LOG(ERROR) << "Failed to acquire the pathname/filename parameter from "
                    "the syscall event";
      continue;
    }

    const auto& opt_var_filename = opt_var_it->second;
    std::string filename = {};
    if (opt_var_filename.has_value()) {
      const auto& variant = opt_var_filename.value();
      if (std::holds_alternative<std::string>(variant)) {
        filename = std::get<std::string>(variant);
      }
    }

    new_event.executable_path = std::move(filename);
    syscall_event_list.push_back(std::move(new_event));
  }

  return syscall_event_list;
}
} // namespace osquery
