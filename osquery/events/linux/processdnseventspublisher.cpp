/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <array>

#include <osquery/events/linux/processdnseventspublisher.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/utils/conversions/tryto.h>

#include <ebpfpub/ifunctiontracer.h>

#include <sys/resource.h>

namespace tob::ebpfpub {
namespace {
static const std::string kSerializerName{"getaddrinfo"};

StringErrorOr<std::string> bufferStorageEntryToString(
    std::uint64_t index, IBufferStorage& buffer_storage) {
  auto L_getStringLength =
      [](const std::vector<std::uint8_t>& buffer) -> std::size_t {
    auto buffer_ptr = buffer.data();

    std::size_t length = 0;
    while (length < buffer.size() && buffer_ptr[length] != '\x00') {
      ++length;
    }

    return length;
  };

  std::vector<std::uint8_t> buffer;

  auto buffer_storage_err = buffer_storage.getBuffer(buffer, index);
  if (!buffer_storage_err.succeeded()) {
    return StringError::create("Failed to acquire the buffer");
  }

  auto length = L_getStringLength(buffer);
  if (length == 0U) {
    return std::string();
  }

  std::string output;
  output.resize(length);

  std::memcpy(&output[0], buffer.data(), length);
  return output;
}
} // namespace

class GetaddrinfoSerializer final : public IFunctionSerializer {
 public:
  static StringErrorOr<IFunctionSerializer::Ref> create() {
    try {
      return Ref(new GetaddrinfoSerializer());

    } catch (const std::bad_alloc&) {
      return StringError::create("Memory allocation failure");

    } catch (const StringError& error) {
      return error;
    }
  }

  virtual ~GetaddrinfoSerializer() override {}

  const std::string& name() const {
    return kSerializerName;
  }

  SuccessOrStringError generate(const ebpf::Structure& enter_structure,
                                IBPFProgramWriter& bpf_prog_writer) {
    // Take the event entry
    auto value_exp = bpf_prog_writer.value("event_entry");
    if (!value_exp.succeeded()) {
      return StringError::create("The event_entry value is not set");
    }

    auto event_entry = value_exp.takeValue();

    // Take the function ptr
    auto exit_function_exp = bpf_prog_writer.getExitFunction();
    if (!exit_function_exp.succeeded()) {
      return exit_function_exp.error();
    }

    auto exit_function = exit_function_exp.takeValue();

    // Take the event data structure
    auto& builder = bpf_prog_writer.builder();
    auto& context = bpf_prog_writer.context();

    auto event_data = builder.CreateGEP(
        event_entry, {builder.getInt32(0), builder.getInt32(1)});

    // Take the event header structure
    auto event_header = builder.CreateGEP(
        event_entry, {builder.getInt32(0), builder.getInt32(0)});

    // Capture the 'prompt' parameter
    auto named_basic_block = llvm::BasicBlock::Create(
        context, "capture_string_prompt", exit_function);

    builder.CreateBr(named_basic_block);
    builder.SetInsertPoint(named_basic_block);

    auto memory_pointer = builder.CreateGEP(
        event_data, {builder.getInt32(0), builder.getInt32(0)});

    auto success_exp = bpf_prog_writer.captureString(memory_pointer);
    if (success_exp.failed()) {
      return success_exp.error();
    }

    // Capture the returned pointer
    named_basic_block = llvm::BasicBlock::Create(
        context, "capture_string_return_value", exit_function);

    builder.CreateBr(named_basic_block);
    builder.SetInsertPoint(named_basic_block);

    memory_pointer = builder.CreateGEP(
        event_header, {builder.getInt32(0), builder.getInt32(5)});

    success_exp = bpf_prog_writer.captureString(memory_pointer);
    if (success_exp.failed()) {
      return success_exp.error();
    }

    return {};
  }

  SuccessOrStringError parseEvents(IFunctionSerializer::Event& event,
                                   IBufferReader& buffer_reader,
                                   IBufferStorage& buffer_storage) {
    // Get the 'node' parameter
    IFunctionSerializer::Event::Variant event_value = {};

    IFunctionSerializer::Event::Integer string_ptr;
    string_ptr.type = IFunctionSerializer::Event::Integer::Type::Int64;
    string_ptr.is_signed = false;
    string_ptr.value = buffer_reader.u64();

    bool save_raw_str_pointer{true};
    if ((string_ptr.value >> 56) == 0xFF) {
      auto string_exp =
          bufferStorageEntryToString(string_ptr.value, buffer_storage);

      if (string_exp.succeeded()) {
        event_value = string_exp.takeValue();
        save_raw_str_pointer = false;
      }
    }

    if (save_raw_str_pointer) {
      event_value = string_ptr;
    }

    event.field_map.insert({"node", std::move(event_value)});

    // Get the 'service' parameter
    event_value = {};

    string_ptr = {};
    string_ptr.type = IFunctionSerializer::Event::Integer::Type::Int64;
    string_ptr.is_signed = false;
    string_ptr.value = buffer_reader.u64();

    save_raw_str_pointer = true;
    if ((string_ptr.value >> 56) == 0xFF) {
      auto string_exp =
          bufferStorageEntryToString(string_ptr.value, buffer_storage);

      if (string_exp.succeeded()) {
        event_value = string_exp.takeValue();
        save_raw_str_pointer = false;
      }
    }

    if (save_raw_str_pointer) {
      event_value = string_ptr;
    }

    event.field_map.insert({"service", std::move(event_value)});

    return {};
  }

 private:
  GetaddrinfoSerializer() = default;
};
} // namespace tob::ebpfpub

namespace osquery {
namespace {
// clang-format off
const tob::ebpf::Structure kDNSArgumentList = {
  { "const char *", "node", 0U, 8U, false },
  { "const char *", "service", 8U, 8U, false },
  { "const struct addrinfo *", "hints", 16U, 8U, false },
  { "struct addrinfo **", "res", 24U, 8U, false }
};
// clang-format on
} // namespace

FLAG(bool,
     enable_process_dns_events,
     false,
     "Enables the process_dns_events publisher");

REGISTER(ProcessDNSEventsPublisher,
         "event_publisher",
         "processdnseventspublisher");

Status ProcessDNSEventsPublisher::setUp() {
  if (!FLAGS_enable_process_dns_events) {
    return Status::failure("Publisher disabled via configuration");
  }

  struct rlimit rl = {};
  rl.rlim_max = RLIM_INFINITY;
  rl.rlim_cur = rl.rlim_max;

  auto err = setrlimit(RLIMIT_MEMLOCK, &rl);
  if (err != 0) {
    return Status::failure("Failed to setup the memory lock limits");
  }

  auto buffer_storage_exp = tob::ebpfpub::IBufferStorage::create(4096U, 100U);
  if (!buffer_storage_exp.succeeded()) {
    return Status::failure("Failed to create the buffer storage");
  }

  buffer_storage = buffer_storage_exp.takeValue();

  auto perf_event_array_exp = tob::ebpf::PerfEventArray::create(11U);

  if (!perf_event_array_exp.succeeded()) {
    return Status::failure("Failed to create the perf event array");
  }

  perf_event_array = perf_event_array_exp.takeValue();

  auto perf_event_reader_exp = tob::ebpfpub::IPerfEventReader::create(
      *perf_event_array.get(), *buffer_storage.get());

  if (!perf_event_reader_exp.succeeded()) {
    return Status::failure("Failed to create the perf event reader");
  }

  perf_event_reader = perf_event_reader_exp.takeValue();

  auto serializer_exp = tob::ebpfpub::GetaddrinfoSerializer::create();
  if (!serializer_exp.succeeded()) {
    const auto& error = serializer_exp.error();
    return Status::failure(error.message());
  }

  auto serializer = serializer_exp.takeValue();

  auto function_tracer_exp = tob::ebpfpub::IFunctionTracer::createFromUprobe(
      "getaddrinfo",
      "/lib/x86_64-linux-gnu/libc.so.6",
      kDNSArgumentList,
      *buffer_storage.get(),
      *perf_event_array.get(),
      256U,
      std::move(serializer));

  if (!function_tracer_exp.succeeded()) {
    const auto& error = function_tracer_exp.error();
    return Status::failure(error.message());
  }

  auto function_tracer = function_tracer_exp.takeValue();
  perf_event_reader->insert(std::move(function_tracer));

  return Status::success();
}

void ProcessDNSEventsPublisher::configure() {
  if (!FLAGS_enable_process_dns_events) {
    return;
  }
}

void ProcessDNSEventsPublisher::tearDown() {
  if (!FLAGS_enable_process_dns_events) {
    return;
  }
}

Status ProcessDNSEventsPublisher::run() {
  if (!FLAGS_enable_process_dns_events) {
    return Status::failure("Publisher disabled via configuration");
  }

  std::atomic_bool terminate{false};
  auto event_context = createEventContext();

  // clang-format off
  auto success_exp = perf_event_reader->exec(
    terminate,

    [&event_context](const tob::ebpfpub::IFunctionSerializer::EventList &event_list) -> void {
      for (const auto &event : event_list) {
        ProcessDNSEvent new_event = {};
        new_event.timestamp = event.header.timestamp;

        new_event.user_id = event.header.user_id;
        new_event.group_id = event.header.group_id;

        new_event.process_id = event.header.process_id;
        new_event.thread_id = event.header.thread_id;

        new_event.exit_code = event.header.exit_code;

        auto node_field_opt_it = event.field_map.find("node");
        if (node_field_opt_it != event.field_map.end()) {
          const auto node_field_opt = node_field_opt_it->second;

          if (node_field_opt.has_value()) {
            const auto &node_field_var = node_field_opt.value();

            if (std::holds_alternative<std::string>(node_field_var)) {
              const auto &node_value = std::get<std::string>(node_field_var);
              new_event.node = node_value;
            }
          }
        }

        auto service_field_opt_it = event.field_map.find("service");
        if (service_field_opt_it != event.field_map.end()) {
          const auto service_field_opt = service_field_opt_it->second;

          if (service_field_opt.has_value()) {
            const auto &service_field_var = service_field_opt.value();

            if (std::holds_alternative<std::string>(service_field_var)) {
              const auto &service_value = std::get<std::string>(service_field_var);
              new_event.service = service_value;
            }
          }
        }


        event_context->event_list.push_back(std::move(new_event));
      }
    }
  );
  // clang-format on

  if (success_exp.failed()) {
    const auto& error = success_exp.error();
    return Status::failure(error.message());
  }

  if (!event_context->event_list.empty()) {
    fire(event_context);
  }

  return Status::success();
}

ProcessDNSEventsPublisher::~ProcessDNSEventsPublisher() {
  tearDown();
}
} // namespace osquery
