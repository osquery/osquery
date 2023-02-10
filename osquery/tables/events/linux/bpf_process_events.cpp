/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/events/linux/bpf_process_events.h>

#include <linux/ptrace.h>

#include <boost/algorithm/string.hpp>
#include <rapidjson/document.h>

namespace osquery {

namespace {

#ifndef PTRACE_SET_SYSCALL
#define PTRACE_SET_SYSCALL 23
#endif

#ifndef PTRACE_GET_SYSCALL_INFO
#define PTRACE_GET_SYSCALL_INFO 0x420e
#endif

const std::unordered_map<int, std::string> kCapabilityNameMap = {
    {0, "CAP_CHOWN"},
    {1, "CAP_DAC_OVERRIDE"},
    {2, "CAP_DAC_READ_SEARCH"},
    {3, "CAP_FOWNER"},
    {4, "CAP_FSETID"},
    {5, "CAP_KILL"},
    {6, "CAP_SETGID"},
    {7, "CAP_SETUID"},
    {8, "CAP_SETPCAP"},
    {9, "CAP_LINUX_IMMUTABLE"},
    {10, "CAP_NET_BIND_SERVICE"},
    {11, "CAP_NET_BROADCAST"},
    {12, "CAP_NET_ADMIN"},
    {13, "CAP_NET_RAW"},
    {14, "CAP_IPC_LOCK"},
    {15, "CAP_IPC_OWNER"},
    {16, "CAP_SYS_MODULE"},
    {17, "CAP_SYS_RAWIO"},
    {18, "CAP_SYS_CHROOT"},
    {19, "CAP_SYS_PTRACE"},
    {20, "CAP_SYS_PACCT"},
    {21, "CAP_SYS_ADMIN"},
    {22, "CAP_SYS_BOOT"},
    {23, "CAP_SYS_NICE"},
    {24, "CAP_SYS_RESOURCE"},
    {25, "CAP_SYS_TIME"},
    {26, "CAP_SYS_TTY_CONFIG"},
    {27, "CAP_MKNOD"},
    {28, "CAP_LEASE"},
    {29, "CAP_AUDIT_WRITE"},
    {30, "CAP_AUDIT_CONTROL"},
    {31, "CAP_SETFCAP"},
    {32, "CAP_MAC_OVERRIDE"},
    {33, "CAP_MAC_ADMIN"},
    {34, "CAP_SYSLOG"},
    {35, "CAP_WAKE_ALARM"},
    {36, "CAP_BLOCK_SUSPEND"},
    {37, "CAP_AUDIT_READ"},
    {38, "CAP_PERFMON"},
    {39, "CAP_BPF"},
    {40, "CAP_CHECKPOINT_RESTORE"},
};

const std::unordered_map<std::uint64_t, std::string> kPtraceRequestNameMap{
    {PTRACE_GET_SYSCALL_INFO, "PTRACE_GET_SYSCALL_INFO"},
    {PTRACE_SET_THREAD_AREA, "PTRACE_SET_THREAD_AREA"},
    {PTRACE_GET_THREAD_AREA, "PTRACE_GET_THREAD_AREA"},
    {PTRACE_DETACH, "PTRACE_DETACH"},
    {PTRACE_SECCOMP_GET_FILTER, "PTRACE_SECCOMP_GET_FILTER"},
    {PTRACE_SEIZE, "PTRACE_SEIZE"},
    {PTRACE_ATTACH, "PTRACE_ATTACH"},
    {PTRACE_INTERRUPT, "PTRACE_INTERRUPT"},
    {PTRACE_KILL, "PTRACE_KILL"},
    {PTRACE_LISTEN, "PTRACE_LISTEN"},
    {PTRACE_SYSEMU, "PTRACE_SYSEMU"},
    {PTRACE_SYSEMU_SINGLESTEP, "PTRACE_SYSEMU_SINGLESTEP"},
    {PTRACE_SET_SYSCALL, "PTRACE_SET_SYSCALL"},
    {PTRACE_SINGLESTEP, "PTRACE_SINGLESTEP"},
    {PTRACE_SYSCALL, "PTRACE_SYSCALL"},
    {PTRACE_CONT, "PTRACE_CONT"},
    {PTRACE_GETEVENTMSG, "PTRACE_GETEVENTMSG"},
    {PTRACE_SETOPTIONS, "PTRACE_SETOPTIONS"},
    {PTRACE_SETSIGMASK, "PTRACE_SETSIGMASK"},
    {PTRACE_GETSIGMASK, "PTRACE_GETSIGMASK"},
    {PTRACE_PEEKSIGINFO, "PTRACE_PEEKSIGINFO"},
    {PTRACE_SETSIGINFO, "PTRACE_SETSIGINFO"},
    {PTRACE_GETSIGINFO, "PTRACE_GETSIGINFO"},
    {PTRACE_SETREGSET, "PTRACE_SETREGSET"},
    {PTRACE_SETFPREGS, "PTRACE_SETFPREGS"},
    {PTRACE_SETREGS, "PTRACE_SETREGS"},
    {PTRACE_GETREGSET, "PTRACE_GETREGSET"},
    {PTRACE_GETFPREGS, "PTRACE_GETFPREGS"},
    {PTRACE_GETREGS, "PTRACE_GETREGS"},
    {PTRACE_PEEKDATA, "PTRACE_POKEUSER"},
    {PTRACE_POKEDATA, "PTRACE_POKEDATA"},
    {PTRACE_POKETEXT, "PTRACE_POKETEXT"},
    {PTRACE_PEEKUSR, "PTRACE_PEEKUSER"},
    {PTRACE_PEEKTEXT, "PTRACE_PEEKTEXT"},
    {PTRACE_PEEKDATA, "PTRACE_PEEKDATA"},
    {PTRACE_TRACEME, "PTRACE_TRACEME"},
};

template <typename IndexType>
std::string getNameFromMap(
    const std::unordered_map<IndexType, std::string>& name_map,
    IndexType index) {
  std::string name;

  auto it = name_map.find(index);
  if (it == name_map.end()) {
    name = std::to_string(index);
  } else {
    name = it->second;
  }

  return name;
}

} // namespace

REGISTER(BPFProcessEventSubscriber, "event_subscriber", "bpf_process_events");

Status BPFProcessEventSubscriber::init() {
  auto subscription_context = createSubscriptionContext();
  subscribe(&BPFProcessEventSubscriber::eventCallback, subscription_context);

  return Status::success();
}

Status BPFProcessEventSubscriber::eventCallback(const ECRef& event_context,
                                                const SCRef&) {
  auto row_list = generateRowList(event_context->event_list);
  addBatch(row_list);

  return Status::success();
}

bool BPFProcessEventSubscriber::generateRow(
    Row& row, const ISystemStateTracker::Event& event) {
  static const std::unordered_map<ISystemStateTracker::Event::Type,
                                  bool (*)(Row&,
                                           const ISystemStateTracker::Event&)>
      kGeneratorTable{
          {ISystemStateTracker::Event::Type::Exec, generateExecRow},
          {ISystemStateTracker::Event::Type::Capable, generateCapCapableRow},
          {ISystemStateTracker::Event::Type::Ptrace, generatePtraceRow},
          {ISystemStateTracker::Event::Type::InitModule, generateInitModuleRow},
          {ISystemStateTracker::Event::Type::FinitModule,
           generateFinitModuleRow},
          {ISystemStateTracker::Event::Type::Ioctl, generateIoctlRow},
          {ISystemStateTracker::Event::Type::DeleteModule,
           generateDeleteModuleRow},
      };

  auto generator_it = kGeneratorTable.find(event.type);
  if (generator_it == kGeneratorTable.end()) {
    return false;
  }

  if (!initializeEventRow(row, event)) {
    return false;
  }

  const auto& generator = generator_it->second;
  return generator(row, event);
}

bool BPFProcessEventSubscriber::initializeEventRow(
    Row& row, const ISystemStateTracker::Event& event) {
  row.clear();

  switch (event.type) {
  case ISystemStateTracker::Event::Type::Exec:
    row["event"] = "exec";
    break;

  case ISystemStateTracker::Event::Type::Capable:
    row["event"] = "cap_capable";
    break;

  case ISystemStateTracker::Event::Type::Ptrace:
    row["event"] = "ptrace";
    break;

  case ISystemStateTracker::Event::Type::InitModule:
    row["event"] = "init_module";
    break;

  case ISystemStateTracker::Event::Type::FinitModule:
    row["event"] = "finit_module";
    break;

  case ISystemStateTracker::Event::Type::Ioctl:
    row["event"] = "ioctl";
    break;

  case ISystemStateTracker::Event::Type::DeleteModule:
    row["event"] = "delete_module";
    break;

  case ISystemStateTracker::Event::Type::Fork:
  case ISystemStateTracker::Event::Type::Connect:
  case ISystemStateTracker::Event::Type::Bind:
  case ISystemStateTracker::Event::Type::Listen:
  case ISystemStateTracker::Event::Type::Accept:
    return false;
  }

  row["ntime"] = TEXT(event.bpf_header.timestamp);
  row["tid"] = INTEGER(event.bpf_header.thread_id);
  row["pid"] = INTEGER(event.bpf_header.process_id);
  row["uid"] = INTEGER(event.bpf_header.user_id);
  row["gid"] = INTEGER(event.bpf_header.group_id);
  row["cid"] = INTEGER(event.bpf_header.cgroup_id);
  row["exit_code"] = TEXT(std::to_string(event.bpf_header.exit_code));
  row["probe_error"] = INTEGER(event.bpf_header.probe_error);
  row["parent"] = INTEGER(event.parent_process_id);
  row["path"] = TEXT(event.binary_path);
  row["cwd"] = TEXT(event.cwd);
  row["duration"] = INTEGER(event.bpf_header.duration);

  return true;
}

bool BPFProcessEventSubscriber::generateExecRow(
    Row& row, const ISystemStateTracker::Event& event) {
  if (event.type != ISystemStateTracker::Event::Type::Exec) {
    return false;
  }

  auto signed_exit_code = static_cast<std::int64_t>(event.bpf_header.exit_code);
  if (signed_exit_code >= -EHWPOISON && signed_exit_code <= -EPERM) {
    return false;
  }

  if (!std::holds_alternative<ISystemStateTracker::Event::ExecData>(
          event.data)) {
    VLOG(1) << "Missing ExecData in Exec event";

    row["data"] = "";
    row["json_data"] = "[]";

  } else {
    const auto& exec_data =
        std::get<ISystemStateTracker::Event::ExecData>(event.data);

    row["data"] = generateExecData(exec_data.argv);
    row["json_data"] = generateExecJsonData(exec_data.argv);
  }

  return true;
}

bool BPFProcessEventSubscriber::generateCapCapableRow(
    Row& row, const ISystemStateTracker::Event& event) {
  if (event.type != ISystemStateTracker::Event::Type::Capable) {
    return false;
  }

  if (!std::holds_alternative<ISystemStateTracker::Event::CapableData>(
          event.data)) {
    VLOG(1) << "Missing CapableData in Capable event";

    row["data"] = "";
    row["json_data"] = "{}";

  } else {
    const auto& capable_data =
        std::get<ISystemStateTracker::Event::CapableData>(event.data);

    row["data"] = generateCapCapableData(capable_data);
    row["json_data"] = generateCapCapableJsonData(capable_data);
  }

  return true;
}

bool BPFProcessEventSubscriber::generatePtraceRow(
    Row& row, const ISystemStateTracker::Event& event) {
  if (event.type != ISystemStateTracker::Event::Type::Ptrace) {
    return false;
  }

  if (!std::holds_alternative<ISystemStateTracker::Event::PtraceData>(
          event.data)) {
    VLOG(1) << "Missing PtraceData in Ptrace event";

    row["data"] = "";
    row["json_data"] = "{}";

  } else {
    const auto& ptrace_data =
        std::get<ISystemStateTracker::Event::PtraceData>(event.data);

    row["data"] = generatePtraceData(ptrace_data);
    row["json_data"] = generatePtraceJsonData(ptrace_data);
  }

  return true;
}

bool BPFProcessEventSubscriber::generateInitModuleRow(
    Row& row, const ISystemStateTracker::Event& event) {
  if (event.type != ISystemStateTracker::Event::Type::InitModule) {
    return false;
  }

  if (!std::holds_alternative<ISystemStateTracker::Event::InitModuleData>(
          event.data)) {
    VLOG(1) << "Missing InitModuleData in InitModule event";

    row["data"] = "";
    row["json_data"] = "{}";

  } else {
    const auto& init_module_data =
        std::get<ISystemStateTracker::Event::InitModuleData>(event.data);

    row["data"] = generateInitModuleData(init_module_data);
    row["json_data"] = generateInitModuleJsonData(init_module_data);
  }

  return true;
}

bool BPFProcessEventSubscriber::generateFinitModuleRow(
    Row& row, const ISystemStateTracker::Event& event) {
  if (event.type != ISystemStateTracker::Event::Type::FinitModule) {
    return false;
  }

  if (!std::holds_alternative<ISystemStateTracker::Event::FinitModuleData>(
          event.data)) {
    VLOG(1) << "Missing FinitModuleData in FinitModule event";

    row["data"] = "";
    row["json_data"] = "{}";

  } else {
    const auto& finit_module_data =
        std::get<ISystemStateTracker::Event::FinitModuleData>(event.data);

    row["data"] = generateFinitModuleData(finit_module_data);
    row["json_data"] = generateFinitModuleJsonData(finit_module_data);
  }

  return true;
}

bool BPFProcessEventSubscriber::generateIoctlRow(
    Row& row, const ISystemStateTracker::Event& event) {
  if (event.type != ISystemStateTracker::Event::Type::Ioctl) {
    return false;
  }

  if (!std::holds_alternative<ISystemStateTracker::Event::IoctlData>(
          event.data)) {
    VLOG(1) << "Missing IoctlData in Ioctl event";

    row["data"] = "";
    row["json_data"] = "{}";

  } else {
    const auto& ioctl_data =
        std::get<ISystemStateTracker::Event::IoctlData>(event.data);

    row["data"] = generateIoctlData(ioctl_data);
    row["json_data"] = generateIoctlJsonData(ioctl_data);
  }

  return true;
}

bool BPFProcessEventSubscriber::generateDeleteModuleRow(
    Row& row, const ISystemStateTracker::Event& event) {
  if (event.type != ISystemStateTracker::Event::Type::DeleteModule) {
    return false;
  }

  if (!std::holds_alternative<ISystemStateTracker::Event::DeleteModuleData>(
          event.data)) {
    VLOG(1) << "Missing DeleteModuleData in DeleteModule event";

    row["data"] = "";
    row["json_data"] = "{}";

  } else {
    const auto& delete_module_data =
        std::get<ISystemStateTracker::Event::DeleteModuleData>(event.data);

    row["data"] = generateDeleteModuleData(delete_module_data);
    row["json_data"] = generateDeleteModuleJsonData(delete_module_data);
  }

  return true;
}

std::vector<Row> BPFProcessEventSubscriber::generateRowList(
    const ISystemStateTracker::EventList& event_list) {
  std::vector<Row> row_list;

  for (const auto& event : event_list) {
    Row row = {};
    if (generateRow(row, event)) {
      row_list.push_back(std::move(row));
    }
  }

  return row_list;
}

std::string BPFProcessEventSubscriber::generateExecData(
    const std::vector<std::string>& argv) {
  std::string output;

  for (auto param_it = argv.begin(); param_it != argv.end(); ++param_it) {
    const auto& arg = *param_it;

    // clang-format off
    auto whitespace_it = std::find_if(
      arg.begin(),
      arg.end(),
      
      [](const char &c) -> bool {
        return std::isspace(c);
      }
    );
    // clang-format on

    if (whitespace_it != arg.end()) {
      output += '\'';
    }

    output += arg;

    if (whitespace_it != arg.end()) {
      output += '\'';
    }

    if (std::next(param_it, 1) != argv.end()) {
      output += ' ';
    }
  }

  return output;
}

std::string BPFProcessEventSubscriber::generateExecJsonData(
    const std::vector<std::string>& argv) {
  rapidjson::Document document;
  document.SetArray();

  auto& allocator = document.GetAllocator();
  for (const auto& arg : argv) {
    rapidjson::Value value = {};
    value.SetString(arg, allocator);

    document.PushBack(value, allocator);
  }

  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

  document.Accept(writer);
  return buffer.GetString();
}

std::string BPFProcessEventSubscriber::generateCapCapableData(
    const ISystemStateTracker::Event::CapableData& data) {
  return "capability=" + getNameFromMap(kCapabilityNameMap, data.capability);
}

std::string BPFProcessEventSubscriber::generateCapCapableJsonData(
    const ISystemStateTracker::Event::CapableData& data) {
  return "{\"capability\":\"" +
         getNameFromMap(kCapabilityNameMap, data.capability) + "\"}";
}

std::string BPFProcessEventSubscriber::generatePtraceData(
    const ISystemStateTracker::Event::PtraceData& data) {
  return "request=" + getNameFromMap(kPtraceRequestNameMap, data.request) +
         " thread_id=" + std::to_string(data.thread_id);
}

std::string BPFProcessEventSubscriber::generatePtraceJsonData(
    const ISystemStateTracker::Event::PtraceData& data) {
  return "{\"request\":\"" +
         getNameFromMap(kPtraceRequestNameMap, data.request) +
         "\",\"thread_id\":" + std::to_string(data.thread_id) + "}";
}

std::string BPFProcessEventSubscriber::generateInitModuleData(
    const ISystemStateTracker::Event::InitModuleData& data) {
  std::stringstream stream;
  stream << "module_image=0x" << std::hex << data.module_image << " "
         << "len=" << std::dec << data.len << " "
         << "param_values=" << data.param_values;

  return stream.str();
}

std::string BPFProcessEventSubscriber::generateInitModuleJsonData(
    const ISystemStateTracker::Event::InitModuleData& data) {
  std::string module_image;

  {
    std::stringstream stream;
    stream << "0x" << std::hex << data.module_image;

    module_image = stream.str();
  }

  rapidjson::Document document;
  document.SetObject();

  auto& allocator = document.GetAllocator();
  document.AddMember("module_image", module_image, allocator);
  document.AddMember("len", data.len, allocator);
  document.AddMember("param_values", data.param_values, allocator);

  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

  document.Accept(writer);
  return buffer.GetString();
}

std::string BPFProcessEventSubscriber::generateFinitModuleData(
    const ISystemStateTracker::Event::FinitModuleData& data) {
  auto output = "fd=" + std::to_string(data.fd);

  if (data.opt_path.has_value()) {
    output += " path=" + data.opt_path.value();
  }

  output += " param_values=" + data.param_values +
            " flags=" + std::to_string(data.flags);

  return output;
}

std::string BPFProcessEventSubscriber::generateFinitModuleJsonData(
    const ISystemStateTracker::Event::FinitModuleData& data) {
  rapidjson::Document document;
  document.SetObject();

  auto& allocator = document.GetAllocator();
  document.AddMember("fd", data.fd, allocator);

  if (data.opt_path.has_value()) {
    document.AddMember("path", data.opt_path.value(), allocator);
  }

  document.AddMember("param_values", data.param_values, allocator);
  document.AddMember("flags", data.flags, allocator);

  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

  document.Accept(writer);
  return buffer.GetString();
}

std::string BPFProcessEventSubscriber::generateIoctlData(
    const ISystemStateTracker::Event::IoctlData& data) {
  auto str = "fd=" + std::to_string(data.fd);

  if (data.opt_path.has_value()) {
    str += " path=" + data.opt_path.value();
  }

  str += " request=" + std::to_string(data.request);

  return str;
}

std::string BPFProcessEventSubscriber::generateIoctlJsonData(
    const ISystemStateTracker::Event::IoctlData& data) {
  rapidjson::Document document;
  document.SetObject();

  auto& allocator = document.GetAllocator();
  document.AddMember("fd", data.fd, allocator);

  if (data.opt_path.has_value()) {
    document.AddMember("path", data.opt_path.value(), allocator);
  }

  document.AddMember("request", data.request, allocator);

  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

  document.Accept(writer);
  return buffer.GetString();
}

std::string BPFProcessEventSubscriber::generateDeleteModuleData(
    const ISystemStateTracker::Event::DeleteModuleData& data) {
  return "name=" + data.name + " flags=" + std::to_string(data.flags);
}

std::string BPFProcessEventSubscriber::generateDeleteModuleJsonData(
    const ISystemStateTracker::Event::DeleteModuleData& data) {
  rapidjson::Document document;
  document.SetObject();

  auto& allocator = document.GetAllocator();
  document.AddMember("name", data.name, allocator);
  document.AddMember("flags", data.flags, allocator);

  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

  document.Accept(writer);
  return buffer.GetString();
}

} // namespace osquery
