/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/experimental/tracing/linux/syscalls_programs.h>

#include <boost/core/demangle.hpp>

namespace osquery {
namespace events {

namespace {

bool constexpr kIsDebug =
#ifndef NDEBUG
    true;
#else
    false;
#endif

} // namespace

Expected<ebpf::Program, ebpf::Program::Error> genLinuxKillEnterProgram(
    enum bpf_prog_type prog_type, PerfEventCpuMap const& cpu_map) {
  constexpr int kKillEnterSize = 44;
  static_assert(sizeof(syscall::EventType) + sizeof(syscall::Event::pid) +
                        sizeof(syscall::Event::tgid) +
                        sizeof(syscall::Event::Body::KillEnter) ==
                    kKillEnterSize,
                "A program below relies on certain size of output struct");
  // clang-format off
  return ebpf::Program::load({
    //                      code ,  dst reg ,  src reg , offset , immediate constant(k)
    {BPF_ALU64 | BPF_X | BPF_MOV , BPF_REG_6, BPF_REG_1,     0,  0}, // r6 = r1
    {BPF_ALU64 | BPF_K | BPF_MOV , BPF_REG_1,         0,     0,  0}, // r1 = 0

    // this part of the stack is for comm string, let's initialize it with a '\0'
    {BPF_STX | BPF_DW | BPF_MEM  , BPF_REG_10, BPF_REG_1,  -32,  0},
    {BPF_STX | BPF_DW | BPF_MEM  , BPF_REG_10, BPF_REG_1,  -24,  0},

    // put syscall code into final event struct, @see syscall::Event::type
    {BPF_ST  | BPF_W | BPF_MEM   , BPF_REG_10,         0,  -kKillEnterSize,  static_cast<__s32>(syscall::EventType::KillEnter)}, // Event.type

    // call fanction get_current_uid_gid()
    {BPF_JMP | BPF_K | BPF_CALL  ,          0,         0,    0,  BPF_FUNC_get_current_uid_gid},
    // put first [0..32] bits of return value (R0) which is uid into final event struct, offset -8
    {BPF_STX | BPF_W | BPF_MEM   , BPF_REG_10, BPF_REG_0,   -8,  0}, // Event.uid
    {BPF_ALU64 | BPF_K | BPF_RSH ,          0,         0,    0,  32},
    // put first [32..65] bits of return value (R0) which is gid into final event struct, offset -4
    {BPF_STX | BPF_W | BPF_MEM   , BPF_REG_10, BPF_REG_0,   -4,  0}, // Event.gid

    // call fanction get_current_pid_tgid()
    {BPF_JMP | BPF_K | BPF_CALL  ,          0,         0,    0,  BPF_FUNC_get_current_pid_tgid},
    // put first [0..32] bits of return value (R0) which is pid into final event struct, offset -40
    {BPF_STX | BPF_W | BPF_MEM   , BPF_REG_10, BPF_REG_0,  -40,  0}, // Event.body.kill_enter.pid
    {BPF_ALU64 | BPF_K | BPF_RSH ,          0,         0,    0,  32},
    // put first [0..32] bits of return value (R0) which is tgid into final event struct, offset -36
    {BPF_STX | BPF_W | BPF_MEM   , BPF_REG_10, BPF_REG_0,  -36,  0}, // Event.body.kill_enter.tgid

    // put stack pointer (register R10) to register R1, it's gonna be a first argument
    {BPF_ALU64 | BPF_X | BPF_MOV , BPF_REG_1, BPF_REG_10,    0,  0}, // r1 = r10
    // make R1 pointing to Event.body.kill_enter.comm in final event struct, offset -32
    {BPF_ALU64 | BPF_K | BPF_ADD , BPF_REG_1,          0,    0,  -32}, // r1 += -32
    // put size of Event.body.kill_enter.comm to R2, it's gonna be a second argument
    {BPF_ALU64 | BPF_K | BPF_MOV , BPF_REG_2,          0,    0, syscall::kCommSize},
    // call get_current_comm(char *buf=R1, int size_of_buf=R2)
    {BPF_JMP | BPF_K | BPF_CALL  ,         0,          0,    0, BPF_FUNC_get_current_comm}, // call

    // let's read arguments of kill syscall, see /sys/kernel/debug/tracing/events/syscalls/sys_enter_kill/format
    // TODO: It's not portable, because format can differ on different systems, but let me fix it later.
    // load value from ctx + 16 to R7, accordint to format it is PID - first argument of kill()
    {BPF_LDX | BPF_DW | BPF_MEM  , BPF_REG_7,  BPF_REG_6,   16,  0},
    // stor PID from R7 to final event struct on stack
    {BPF_STX | BPF_W | BPF_MEM   , BPF_REG_10, BPF_REG_7,  -16,  0},
    // load value from ctx + 24 to R7, accordint to format it is SIG - second argument of kill()
    {BPF_LDX | BPF_DW | BPF_MEM  , BPF_REG_7,  BPF_REG_6,   24,  0},
    // stor SIG from R7 to final event struct on stack
    {BPF_STX | BPF_W | BPF_MEM   , BPF_REG_10, BPF_REG_7,  -12,  0},

    // let's send everything to user space via perf_event_open()
    // event located on top of the stack, so store pointer to the top of the stack (R10) to R4
    {BPF_ALU64 | BPF_X | BPF_MOV , BPF_REG_4, BPF_REG_10,    0,  0},
    // we need pointer to the beginning of the event, so substruct size of the sending struct from R4
    {BPF_ALU64 | BPF_K | BPF_ADD , BPF_REG_4,          0,    0,  -kKillEnterSize}, // r4 += -kKillEnterSize
    // store ctx to R1
    {BPF_ALU64 | BPF_X | BPF_MOV , BPF_REG_1,  BPF_REG_6,    0,  0},
    // store map with perf_event_open() buffers per CPU to R2
    {BPF_LD | BPF_DW | BPF_IMM   , BPF_REG_2, BPF_PSEUDO_MAP_FD, 0, cpu_map.fd()},
    {BPF_LD | BPF_W | BPF_IMM    ,         0,          0,    0,  0}, // imm is 32, but we loading 64, so this is yet another "smart" trick
    // we don't know current CPU, but kernel can take care of it, put -1 in R2
    {BPF_LD | BPF_DW | BPF_IMM   , BPF_REG_3,          0,    0, -1}, // r2 = -1 -> CPU
    {BPF_LD | BPF_W | BPF_IMM    ,         0,          0,    0,  0}, // imm is 32, but we loading 64, so this is yet another "smart" trick
    // R5 should be a size of the event
    {BPF_ALU64 | BPF_K | BPF_MOV , BPF_REG_5,          0,    0, kKillEnterSize}, // r5 = kKillEnterSize
    // call perf_event_output(ctx=R1, map=R2, flags=R3, data=R4, size=R5)
    {BPF_JMP | BPF_K | BPF_CALL  ,         0,          0,    0, BPF_FUNC_perf_event_output}, // call
    // put 0 as a return value of the program
    {BPF_ALU64 | BPF_K | BPF_MOV , BPF_REG_0,          0,    0,  0}, // r0 = 0
    // let's get out of here
    {BPF_JMP | BPF_K | BPF_EXIT  ,         0,          0,    0,  0}, // exit

  }, BPF_PROG_TYPE_TRACEPOINT, kIsDebug);
  // clang-format on
}

Expected<ebpf::Program, ebpf::Program::Error> genLinuxSetuidEnterProgram(
    enum bpf_prog_type prog_type, PerfEventCpuMap const& cpu_map) {
  constexpr int kSetuidEnterSize = 40;
  static_assert(sizeof(syscall::EventType) + sizeof(syscall::Event::pid) +
                        sizeof(syscall::Event::tgid) +
                        sizeof(syscall::Event::Body::SetuidEnter) ==
                    kSetuidEnterSize,
                "A program below relies on certain size of output struct");
  static_assert(static_cast<__s32>(syscall::EventType::SetuidEnter) ==
                    -static_cast<__s32>(syscall::EventType::SetuidExit),
                "Enter and Exit codes must be convertible to each other by "
                "multiplying to -1");
  // clang-format off
  return ebpf::Program::load({
    //                      code ,  dst reg ,  src reg , offset , immediate constant(k)
    {BPF_ALU64 | BPF_X | BPF_MOV , BPF_REG_6, BPF_REG_1,     0,  0}, // r6 = r1
    {BPF_ALU64 | BPF_K | BPF_MOV , BPF_REG_1,         0,     0,  0}, // r1 = 0

    {BPF_STX | BPF_W | BPF_MEM   , BPF_REG_10, BPF_REG_1,  -28,  0},
    {BPF_STX | BPF_DW | BPF_MEM  , BPF_REG_10, BPF_REG_1,  -24,  0},
    {BPF_STX | BPF_W | BPF_MEM   , BPF_REG_10, BPF_REG_1,  -16,  0},

    // Event.type = SyscallEvent::EventType::SetuidEnter
    {BPF_ST  | BPF_W | BPF_MEM   , BPF_REG_10,         0,  -kSetuidEnterSize,  static_cast<__s32>(syscall::EventType::SetuidEnter)},

    {BPF_JMP | BPF_K | BPF_CALL  ,          0,         0,    0,  BPF_FUNC_get_current_uid_gid},
    {BPF_STX | BPF_W | BPF_MEM   , BPF_REG_10, BPF_REG_0,   -8,  0}, // Event.uid
    {BPF_ALU64 | BPF_K | BPF_RSH ,          0,         0,    0,  32},
    {BPF_STX | BPF_W | BPF_MEM   , BPF_REG_10, BPF_REG_0,   -4,  0}, // Event.gid

    {BPF_JMP | BPF_K | BPF_CALL  ,          0,         0,    0,  BPF_FUNC_get_current_pid_tgid},
    {BPF_STX | BPF_W | BPF_MEM   , BPF_REG_10, BPF_REG_0,  -36,  0}, // Event.body.pid
    {BPF_ALU64 | BPF_K | BPF_RSH ,          0,         0,    0,  32},
    {BPF_STX | BPF_W | BPF_MEM   , BPF_REG_10, BPF_REG_0,  -32,  0}, // Event.body.tgid

    {BPF_ALU64 | BPF_X | BPF_MOV , BPF_REG_1, BPF_REG_10,    0,  0}, // r1 = r10
    {BPF_ALU64 | BPF_K | BPF_ADD , BPF_REG_1,          0,    0,  -28}, // r1 += -36
    {BPF_ALU64 | BPF_K | BPF_MOV , BPF_REG_2,          0,    0, syscall::kCommSize},   // r2 = SyscallEvent::kCommSize
    {BPF_JMP | BPF_K | BPF_CALL  ,         0,          0,    0, BPF_FUNC_get_current_comm}, // call

    {BPF_LDX | BPF_DW | BPF_MEM  , BPF_REG_7,  BPF_REG_6,   16,  0}, // see format: arg uid
    {BPF_STX | BPF_W | BPF_MEM   , BPF_REG_10, BPF_REG_7,  -12,  0}, // Event.body.arg_uid

    {BPF_ALU64 | BPF_X | BPF_MOV , BPF_REG_4, BPF_REG_10,    0,  0}, // r4 = r10
    {BPF_ALU64 | BPF_K | BPF_ADD , BPF_REG_4,          0,    0,  -kSetuidEnterSize}, // r4 += -kSetuidEnterSize
    {BPF_ALU64 | BPF_X | BPF_MOV , BPF_REG_1,  BPF_REG_6,    0,  0}, // r1 = r6
    {BPF_LD | BPF_DW | BPF_IMM   , BPF_REG_2, BPF_PSEUDO_MAP_FD, 0, cpu_map.fd()},
    {BPF_LD | BPF_W | BPF_IMM    ,         0,          0,    0,  0}, // imm is 32, but we loading 64, so this is yet another "smart" trick
    {BPF_LD | BPF_DW | BPF_IMM   , BPF_REG_3,          0,    0, -1}, // r2 = -1 -> CPU
    {BPF_LD | BPF_W | BPF_IMM    ,         0,          0,    0,  0}, // imm is 32, but we loading 64, so this is yet another "smart" trick
    {BPF_ALU64 | BPF_K | BPF_MOV , BPF_REG_5,          0,    0, kSetuidEnterSize}, // r5 = kSetuidEnterSize
    {BPF_JMP | BPF_K | BPF_CALL  ,         0,          0,    0, BPF_FUNC_perf_event_output}, // call
    {BPF_ALU64 | BPF_K | BPF_MOV , BPF_REG_0,          0,    0,  0}, // r0 = 0
    {BPF_JMP | BPF_K | BPF_EXIT  ,         0,          0,    0,  0}, // exit

  }, BPF_PROG_TYPE_TRACEPOINT, kIsDebug);
  // clang-format on
}

Expected<ebpf::Program, ebpf::Program::Error> genLinuxExitProgram(
    enum bpf_prog_type prog_type,
    PerfEventCpuMap const& cpu_map,
    syscall::EventType type) {
  constexpr int kExitSize = 16;
  static_assert(sizeof(syscall::EventType) + sizeof(syscall::Event::pid) +
                        sizeof(syscall::Event::tgid) +
                        sizeof(syscall::Event::Body::Exit) ==
                    kExitSize,
                "A program below relies on certain size of output struct");
  // clang-format off
  return ebpf::Program::load({
    //                      code ,  dst reg ,   src reg , offset , immediate constant(k)
    {BPF_ALU64 | BPF_X | BPF_MOV , BPF_REG_6,  BPF_REG_1,    0, 0}, // r6 = r1
    {BPF_ALU64 | BPF_K | BPF_MOV , BPF_REG_1,          0,    0, 0}, // r1 = 0

    {BPF_ST  | BPF_W | BPF_MEM   , BPF_REG_10,         0,  -kExitSize,  static_cast<__s32>(type)}, // type = syscall::EventType::Exit*

    {BPF_JMP | BPF_K | BPF_CALL  ,          0,         0,    0,  BPF_FUNC_get_current_pid_tgid},
    {BPF_STX | BPF_W | BPF_MEM   , BPF_REG_10, BPF_REG_0,  -12,  0}, // Event.pid
    {BPF_ALU64 | BPF_K | BPF_RSH ,          0,         0,    0, 32}, // r0 >>= 32
    {BPF_STX | BPF_W | BPF_MEM   , BPF_REG_10, BPF_REG_0,   -8,  0}, // Event.tgid

    {BPF_LDX | BPF_DW | BPF_MEM  , BPF_REG_7,  BPF_REG_6,   16,  0}, // see format: ret
    {BPF_STX | BPF_W | BPF_MEM   , BPF_REG_10, BPF_REG_7,   -4,  0}, // Event.body.return_value

    {BPF_ALU64 | BPF_X | BPF_MOV , BPF_REG_4, BPF_REG_10,    0,  0}, // r4 = r10
    {BPF_ALU64 | BPF_K | BPF_ADD , BPF_REG_4,          0,    0, -kExitSize}, // r4 += -kExitSize
    {BPF_ALU64 | BPF_X | BPF_MOV , BPF_REG_1,  BPF_REG_6,    0,  0}, // r1 = r6
    {BPF_LD | BPF_DW | BPF_IMM   , BPF_REG_2, BPF_PSEUDO_MAP_FD, 0, cpu_map.fd()},
    {BPF_LD | BPF_W | BPF_IMM    ,         0,          0,    0,  0}, // imm is 32, but we loading 64, so this is yet another "smart" trick
    {BPF_LD | BPF_DW | BPF_IMM   , BPF_REG_3,          0,    0, -1}, // r2 = -1 -> CPU
    {BPF_LD | BPF_W | BPF_IMM    ,         0,          0,    0,  0}, // imm is 32, but we loading 64, so this is yet another "smart" trick
    {BPF_ALU64 | BPF_K | BPF_MOV , BPF_REG_5,          0,    0,  kExitSize}, // r5 = kExitSize
    {BPF_JMP | BPF_K | BPF_CALL  ,         0,          0,    0,  BPF_FUNC_perf_event_output}, // call
    {BPF_ALU64 | BPF_K | BPF_MOV , BPF_REG_0,          0,    0,  0},  // r0 = 0
    {BPF_JMP | BPF_K | BPF_EXIT  ,         0,          0,    0,  0},  // exit

  }, BPF_PROG_TYPE_TRACEPOINT, kIsDebug);
  // clang-format on
}

Expected<ebpf::Program, ebpf::Program::Error> genLinuxProgram(
    enum bpf_prog_type prog_type,
    PerfEventCpuMap const& cpu_map,
    syscall::EventType type) {
  if (syscall::isEventTypeExit(type)) {
    return genLinuxExitProgram(prog_type, cpu_map, type);
  } else if (syscall::EventType::KillEnter == type) {
    return genLinuxKillEnterProgram(prog_type, cpu_map);
  } else if (syscall::EventType::SetuidEnter == type) {
    return genLinuxSetuidEnterProgram(prog_type, cpu_map);
  } else {
    return createError(ebpf::Program::Error::Unknown)
           << "There is no program for type(" << static_cast<int>(type)
           << ") system call " << boost::core::demangle(typeid(type).name())
           << "(" << static_cast<int>(type) << ")";
  }
}

} // namespace events
} // namespace osquery
