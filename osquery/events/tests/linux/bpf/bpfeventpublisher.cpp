/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "bpftestsmain.h"
#include "mockedprocesscontextfactory.h"
#include "utils.h"

#include <osquery/events/linux/bpf/bpfeventpublisher.h>
#include <osquery/events/linux/bpf/systemstatetracker.h>

#include <fcntl.h>
#include <sys/un.h>

namespace osquery {

namespace {

// clang-format off
const tob::ebpfpub::IFunctionTracer::Event::Header kBaseBPFEventHeader = {
  // timestamp (nsecs from boot)
  1234567890ULL,

  // thread id
  1001,

  // process id
  1001,

  // user id
  1000,

  // group id
  1000,

  // cgroup id
  12345ULL,

  // exit code
  0ULL,

  // probe error flag
  false
};
// clang-format on

// clang-format off
const tob::ebpfpub::IFunctionTracer::Event kBaseBPFEvent = {
  // event identifier
  1,

  // event name
  "",

  // header
  kBaseBPFEventHeader,

  // in field map
  {},

  // out field map
  {}
};
// clang-format on

IProcessContextFactory::Ref getMockedProcessContextFactory() {
  return IProcessContextFactory::Ref(new MockedProcessContextFactory);
}

} // namespace

TEST_F(BPFEventPublisherTests, processForkEvent_and_processVforkEvent) {
  auto state_tracker_ref =
      SystemStateTracker::create(getMockedProcessContextFactory());

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  //
  // Process creations that returned with an error should be ignored
  //

  // fork()
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "fork";
  bpf_event.header.exit_code = -1; // child process id

  auto succeeded =
      BPFEventPublisher::processForkEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // vfork()
  bpf_event.name = "vfork";

  succeeded = BPFEventPublisher::processVforkEvent(state_tracker, bpf_event);
  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  //
  // Valid process creations should update the process context
  //

  // fork()
  bpf_event.name = "fork";
  bpf_event.header.exit_code = 1001; // child process id
  bpf_event.header.process_id = 1000; // parent process id
  succeeded = BPFEventPublisher::processForkEvent(state_tracker, bpf_event);
  EXPECT_TRUE(succeeded);

  // We should now have 2 entries: the parent process 1000, and the child
  // process 1001
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 3U);

  // vfork()
  bpf_event.name = "vfork";
  bpf_event.header.exit_code = 1002; // child process id
  bpf_event.header.process_id = 1001; // parent process id
  succeeded = BPFEventPublisher::processVforkEvent(state_tracker, bpf_event);
  EXPECT_TRUE(succeeded);

  // We should now have one additional process map entry for pid 1002
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 4U);
}

TEST_F(BPFEventPublisherTests, processCloneEvent) {
  auto state_tracker_ref =
      SystemStateTracker::create(getMockedProcessContextFactory());

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  // Processing should fail if the clone_flags parameter is missing
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "clone";

  auto succeeded =
      BPFEventPublisher::processCloneEvent(state_tracker, bpf_event);

  EXPECT_FALSE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Add the clone_flags parameter, but update the exit code so that it
  // appears that the syscall has failed. This event should be ignored

  // clang-format off
  bpf_event.in_field_map.insert(
    {
      "clone_flags",

      {
        "clone_flags",
        true,
        0ULL
      }
    }
  );
  // clang-format on

  bpf_event.header.exit_code = -1; // child process id

  succeeded = BPFEventPublisher::processCloneEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Update the exit code so that the syscall succeeds. This should now
  // add two new entries to the process context map, one for the parent
  // and one for the child process
  bpf_event.header.exit_code = 1001; // child process id
  bpf_event.header.process_id = 1000; // parent process id

  succeeded = BPFEventPublisher::processCloneEvent(state_tracker, bpf_event);
  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 3U);

  // Update the flags so that the syscall creates a thread; this should
  // be ignored
  bpf_event.in_field_map.at("clone_flags").data_var =
      static_cast<std::uint64_t>(CLONE_THREAD);

  succeeded = BPFEventPublisher::processCloneEvent(state_tracker, bpf_event);
  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 3U);
}

TEST_F(BPFEventPublisherTests, processExecveEvent) {
  auto state_tracker_ref =
      SystemStateTracker::create(getMockedProcessContextFactory());

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "execve";

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field filename_field = {
    "filename",
    true,
    "/usr/bin/zsh"
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field argv_field = {
    "argv",
    true,

    std::vector<std::string> {
      "zsh",
      "-H",
      "-i"
    }
  };
  // clang-format on

  for (std::size_t i = 0U; i < 3; ++i) {
    bpf_event.in_field_map = {};

    if ((i & 1) != 0) {
      bpf_event.in_field_map.insert({filename_field.name, filename_field});
    }

    if ((i & 2) != 0) {
      bpf_event.in_field_map.insert({argv_field.name, argv_field});
    }

    auto succeeded =
        BPFEventPublisher::processExecveEvent(state_tracker, bpf_event);

    EXPECT_FALSE(succeeded);
    EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);
  }

  // Now try again with both parameters
  bpf_event.in_field_map.insert({filename_field.name, filename_field});
  bpf_event.in_field_map.insert({argv_field.name, argv_field});

  auto succeeded =
      BPFEventPublisher::processExecveEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);

  // We should now have a new entry for the process that called execve
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 2U);
}

TEST_F(BPFEventPublisherTests, processExecveatEvent) {
  auto state_tracker_ref =
      SystemStateTracker::create(getMockedProcessContextFactory());

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "execveat";

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field filename_field = {
    "filename",
    true,
    "/usr/bin/zsh"
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field argv_field = {
    "argv",
    true,

    std::vector<std::string> {
      "zsh",
      "-H",
      "-i"
    }
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field flags_field = {
    "flags",
    true,
    0ULL
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field fd_field = {
    "fd",
    true,
    static_cast<std::uint64_t>(AT_FDCWD)
  };
  // clang-format on

  for (std::size_t i = 0U; i < 0x0F; ++i) {
    bpf_event.in_field_map = {};

    if ((i & 1) != 0) {
      bpf_event.in_field_map.insert({filename_field.name, filename_field});
    }

    if ((i & 2) != 0) {
      bpf_event.in_field_map.insert({argv_field.name, argv_field});
    }

    if ((i & 4) != 0) {
      bpf_event.in_field_map.insert({flags_field.name, flags_field});
    }

    if ((i & 8) != 0) {
      bpf_event.in_field_map.insert({fd_field.name, fd_field});
    }

    auto succeeded =
        BPFEventPublisher::processExecveatEvent(state_tracker, bpf_event);

    EXPECT_FALSE(succeeded);
    EXPECT_TRUE(state_tracker.eventList().empty());
  }

  // Try again with all the parameters
  bpf_event.in_field_map.insert({filename_field.name, filename_field});
  bpf_event.in_field_map.insert({argv_field.name, argv_field});
  bpf_event.in_field_map.insert({flags_field.name, flags_field});
  bpf_event.in_field_map.insert({fd_field.name, fd_field});

  auto succeeded =
      BPFEventPublisher::processExecveatEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);

  succeeded = BPFEventPublisher::processExecveatEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);

  // We should now have a new entry for the process that called execveat
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 2U);
}

TEST_F(BPFEventPublisherTests, processCloseEvent) {
  auto state_tracker_ref =
      SystemStateTracker::create(getMockedProcessContextFactory());

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "close";
  bpf_event.header.process_id = 2;

  auto succeeded =
      BPFEventPublisher::processCloseEvent(state_tracker, bpf_event);

  EXPECT_FALSE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Try with an invalid fd value. This will be ignored

  // clang-format off
  bpf_event.in_field_map.insert(
    {
      "fd",

      {
        "fd",
        true,
        static_cast<std::uint64_t>(-1)
      }
    }
  );
  // clang-format on

  succeeded = BPFEventPublisher::processCloseEvent(state_tracker, bpf_event);
  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Now try again with a valid fd parameter
  bpf_event.in_field_map.at("fd").data_var = 15ULL;

  succeeded = BPFEventPublisher::processCloseEvent(state_tracker, bpf_event);
  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should now only have 7 file descriptors in the mocked process context
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 7U);
}

TEST_F(BPFEventPublisherTests, processDupEvent) {
  auto state_tracker_ref =
      SystemStateTracker::create(getMockedProcessContextFactory());

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "dup";
  bpf_event.header.process_id = 2;

  auto succeeded = BPFEventPublisher::processDupEvent(state_tracker, bpf_event);

  EXPECT_FALSE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Try with an invalid fd value. This will be ignored
  // clang-format off
  bpf_event.in_field_map.insert(
    {
      "fildes",

      {
        "fildes",
        true,
        static_cast<std::uint64_t>(-1)
      }
    }
  );
  // clang-format on

  succeeded = BPFEventPublisher::processDupEvent(state_tracker, bpf_event);
  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 8U);

  // Now try again with a valid fd parameter, but set the return value so that
  // the syscall fails
  bpf_event.header.exit_code = static_cast<std::uint64_t>(-1);

  bpf_event.in_field_map.at("fildes").data_var = 15ULL;
  succeeded = BPFEventPublisher::processDupEvent(state_tracker, bpf_event);
  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 8U);

  // Fix the exit code so that the syscall succeeds.
  bpf_event.header.exit_code = 16ULL;
  succeeded = BPFEventPublisher::processDupEvent(state_tracker, bpf_event);
  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 9U);
}

TEST_F(BPFEventPublisherTests, processDup2Event) {
  auto state_tracker_ref =
      SystemStateTracker::create(getMockedProcessContextFactory());

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "dup2";
  bpf_event.header.process_id = 2;

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field oldfd_field = {
    "oldfd",
    true,
    15ULL
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field newfd_field = {
    "newfd",
    true,
    16ULL
  };
  // clang-format on

  for (std::size_t i = 0U; i < 3; ++i) {
    bpf_event.in_field_map = {};

    if ((i & 1) != 0) {
      bpf_event.in_field_map.insert({oldfd_field.name, oldfd_field});
    }

    if ((i & 2) != 0) {
      bpf_event.in_field_map.insert({newfd_field.name, newfd_field});
    }

    auto succeeded =
        BPFEventPublisher::processDup2Event(state_tracker, bpf_event);

    EXPECT_FALSE(succeeded);
    EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);
  }

  // Now try again with both parameters but set the exit_code so that
  // the syscall fails
  bpf_event.header.exit_code = static_cast<std::uint64_t>(-1);

  bpf_event.in_field_map.insert({oldfd_field.name, oldfd_field});
  bpf_event.in_field_map.insert({newfd_field.name, newfd_field});

  auto succeeded =
      BPFEventPublisher::processDup2Event(state_tracker, bpf_event);
  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should still have only 8 file descriptors
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 8U);

  // Finally, set the exit code correctly and try again
  bpf_event.header.exit_code = 0;

  succeeded = BPFEventPublisher::processDup2Event(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should now have a new file descriptor in the process context
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 9U);
}

TEST_F(BPFEventPublisherTests, processDup3Event) {
  auto state_tracker_ref =
      SystemStateTracker::create(getMockedProcessContextFactory());

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "dup3";
  bpf_event.header.process_id = 2;

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field oldfd_field = {
    "oldfd",
    true,
    15ULL
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field newfd_field = {
    "newfd",
    true,
    16ULL
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field flags_field = {
    "flags",
    true,
    0ULL
  };
  // clang-format on

  for (std::size_t i = 0U; i < 7; ++i) {
    bpf_event.in_field_map = {};

    if ((i & 1) != 0) {
      bpf_event.in_field_map.insert({oldfd_field.name, oldfd_field});
    }

    if ((i & 2) != 0) {
      bpf_event.in_field_map.insert({newfd_field.name, newfd_field});
    }

    if ((i & 4) != 0) {
      bpf_event.in_field_map.insert({flags_field.name, flags_field});
    }

    auto succeeded =
        BPFEventPublisher::processDup3Event(state_tracker, bpf_event);

    EXPECT_FALSE(succeeded);
    EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);
  }

  // Now try again with all parameters but set the exit_code so that
  // the syscall fails
  bpf_event.header.exit_code = static_cast<std::uint64_t>(-1);

  bpf_event.in_field_map.insert({oldfd_field.name, oldfd_field});
  bpf_event.in_field_map.insert({newfd_field.name, newfd_field});
  bpf_event.in_field_map.insert({flags_field.name, flags_field});

  auto succeeded =
      BPFEventPublisher::processDup3Event(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should still have only 8 file descriptors
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 8U);

  // Finally, set the exit code correctly and try again
  bpf_event.header.exit_code = 0;

  succeeded = BPFEventPublisher::processDup3Event(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should now have a new file descriptor in the process context
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 9U);
}

TEST_F(BPFEventPublisherTests, processCreatEvent) {
  auto state_tracker_ref =
      SystemStateTracker::create(getMockedProcessContextFactory());

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "creat";
  bpf_event.header.process_id = 2;

  auto succeeded =
      BPFEventPublisher::processCreatEvent(state_tracker, bpf_event);

  EXPECT_FALSE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Now try again with the parameter but set the exit_code so that
  // the syscall fails
  bpf_event.header.exit_code = static_cast<std::uint64_t>(-1);

  // clang-format off
  bpf_event.out_field_map.insert(
    {
      "pathname",

      {
        "pathname",
        true,
        "/home/alessandro/test_file.txt"
      }
    }
  );
  // clang-format on

  succeeded = BPFEventPublisher::processCreatEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should still have only 8 file descriptors
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 8U);

  // Finally, set the exit code correctly and try again
  bpf_event.header.exit_code = 16ULL;

  succeeded = BPFEventPublisher::processCreatEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should now have a new file descriptor in the process context
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 9U);
}

TEST_F(BPFEventPublisherTests, processMknodatEvent) {
  auto state_tracker_ref =
      SystemStateTracker::create(getMockedProcessContextFactory());

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass the mandatory parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "mknodat";
  bpf_event.header.exit_code = 1000ULL;

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field mode_field = {
    "mode",
    true,
    static_cast<std::uint64_t>(S_IFREG)
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field filename_field = {
    "filename",
    true,
    "/home/alessandro/test_file"
  };
  // clang-format on

  for (std::size_t i = 0U; i < 3; ++i) {
    bpf_event.in_field_map = {};

    if ((i & 1) != 0) {
      bpf_event.in_field_map.insert({mode_field.name, mode_field});
    }

    if ((i & 2) != 0) {
      bpf_event.out_field_map.insert({filename_field.name, filename_field});
    }

    auto succeeded =
        BPFEventPublisher::processMknodatEvent(state_tracker, bpf_event);

    EXPECT_FALSE(succeeded);
    EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);
  }

  // Now try again with all parameters but set the exit_code so that
  // the syscall fails. This event should now be discarded
  bpf_event.header.exit_code = static_cast<std::uint64_t>(-1);

  bpf_event.in_field_map.insert({mode_field.name, mode_field});
  bpf_event.out_field_map.insert({filename_field.name, filename_field});

  auto succeeded =
      BPFEventPublisher::processMknodatEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Update the exit code again, so that the syscall fails. Pass the modes
  // that we know should be ignored
  bpf_event.header.exit_code = static_cast<std::uint64_t>(9999);
  bpf_event.in_field_map["mode"].data_var = static_cast<std::uint64_t>(S_IFCHR);

  succeeded = BPFEventPublisher::processMknodatEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  bpf_event.in_field_map["mode"].data_var = static_cast<std::uint64_t>(S_IFBLK);

  succeeded = BPFEventPublisher::processMknodatEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Update the mode parameter so that the syscall creates a new regular
  // file. This should finally succeed
  bpf_event.in_field_map["mode"].data_var = static_cast<std::uint64_t>(S_IFREG);

  succeeded = BPFEventPublisher::processMknodatEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 2U);

  {
    auto context = state_tracker.getContextCopy();
    const auto& process = context.process_map.at(bpf_event.header.process_id);
    EXPECT_EQ(process.fd_map.size(), 9U);
  }

  // Change the exit code to another file descriptor. Add the optional dirfd
  // parameter using the fd we just created

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field opt_dirfd_field = {
    "dirfd",
    true,
    static_cast<std::uint64_t>(bpf_event.header.exit_code)
  };
  // clang-format on

  bpf_event.in_field_map.insert({opt_dirfd_field.name, opt_dirfd_field});
  bpf_event.header.exit_code = static_cast<std::uint64_t>(10000);

  succeeded = BPFEventPublisher::processMknodatEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 2U);

  {
    auto context = state_tracker.getContextCopy();
    const auto& process = context.process_map.at(bpf_event.header.process_id);
    EXPECT_EQ(process.fd_map.size(), 10U);
  }
}

TEST_F(BPFEventPublisherTests, processOpenEvent) {
  auto state_tracker_ref =
      SystemStateTracker::create(getMockedProcessContextFactory());

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "open";
  bpf_event.header.process_id = 2;

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field flags_field = {
    "flags",
    true,
    0ULL
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field filename_field = {
    "filename",
    true,
    "/home/alessandro/test_file.txt"
  };
  // clang-format on

  for (std::size_t i = 0U; i < 3; ++i) {
    bpf_event.in_field_map = {};

    if ((i & 1) != 0) {
      bpf_event.in_field_map.insert({flags_field.name, flags_field});
    }

    if ((i & 2) != 0) {
      bpf_event.out_field_map.insert({filename_field.name, filename_field});
    }

    auto succeeded =
        BPFEventPublisher::processOpenEvent(state_tracker, bpf_event);

    EXPECT_FALSE(succeeded);
    EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);
  }

  // Now try again with all parameters but set the exit_code so that
  // the syscall fails
  bpf_event.header.exit_code = static_cast<std::uint64_t>(-1);

  bpf_event.out_field_map.insert({filename_field.name, filename_field});
  bpf_event.in_field_map.insert({flags_field.name, flags_field});

  auto succeeded =
      BPFEventPublisher::processOpenEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should still have only 8 file descriptors
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 8U);

  // Finally, set the exit code correctly and try again
  bpf_event.header.exit_code = 16ULL;

  succeeded = BPFEventPublisher::processOpenEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should now have a new file descriptor in the process context
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 9U);
}

void testOpenAtEventCommon(
    const std::string& event_name,
    const tob::ebpfpub::IFunctionTracer::Event::Field& field1,
    const tob::ebpfpub::IFunctionTracer::Event::Field& field2,
    const tob::ebpfpub::IFunctionTracer::Event::Field& field3) {
  ASSERT_TRUE(event_name == "openat" || event_name == "openat2");

  auto state_tracker_ref =
      SystemStateTracker::create(getMockedProcessContextFactory());

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = event_name;
  bpf_event.header.process_id = 2;

  for (std::size_t i = 0U; i < 7; ++i) {
    bpf_event.in_field_map = {};
    bpf_event.out_field_map = {};

    if ((i & 1) != 0) {
      bpf_event.out_field_map.insert({field1.name, field1});
    }

    if ((i & 2) != 0) {
      bpf_event.in_field_map.insert({field2.name, field2});
    }

    if ((i & 4) != 0) {
      bpf_event.in_field_map.insert({field3.name, field3});
    }

    bool succeeded{};
    if (event_name == "openat") {
      succeeded =
          BPFEventPublisher::processOpenatEvent(state_tracker, bpf_event);

    } else {
      succeeded =
          BPFEventPublisher::processOpenat2Event(state_tracker, bpf_event);
    }

    EXPECT_FALSE(succeeded);
    EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);
  }

  // Now try again with all parameters but set the exit_code so that
  // the syscall fails
  bpf_event.header.exit_code = static_cast<std::uint64_t>(-1);

  bpf_event.out_field_map.insert({field1.name, field1});
  bpf_event.in_field_map.insert({field2.name, field2});
  bpf_event.in_field_map.insert({field3.name, field3});

  bool succeeded{};
  if (event_name == "openat") {
    succeeded = BPFEventPublisher::processOpenatEvent(state_tracker, bpf_event);

  } else {
    succeeded =
        BPFEventPublisher::processOpenat2Event(state_tracker, bpf_event);
  }

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should still have only 8 file descriptors
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 8U);

  // Finally, set the exit code correctly and try again
  bpf_event.header.exit_code = 16ULL;

  if (event_name == "openat") {
    succeeded = BPFEventPublisher::processOpenatEvent(state_tracker, bpf_event);

  } else {
    succeeded =
        BPFEventPublisher::processOpenat2Event(state_tracker, bpf_event);
  }

  ASSERT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should now have a new file descriptor in the process context
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 9U);
}

TEST_F(BPFEventPublisherTests, processOpenatEvent) {
  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field flags_field = {
    "flags",
    true,
    0ULL
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field filename_field = {
    "filename",
    false,
    "/home/alessandro/test_file.txt"
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field dfd_field = {
    "dfd",
    true,
    15ULL
  };
  // clang-format on

  testOpenAtEventCommon("openat", filename_field, flags_field, dfd_field);
}

TEST_F(BPFEventPublisherTests, processOpenat2Event) {
  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field how_field = {
    "how",
    true,
    std::vector<std::uint8_t>(24, 0)
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field filename_field = {
    "filename",
    false,
    "/home/alessandro/test_file.txt"
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field dfd_field = {
    "dfd",
    true,
    15ULL
  };
  // clang-format on

  testOpenAtEventCommon("openat2", filename_field, how_field, dfd_field);
}

TEST_F(BPFEventPublisherTests, processChdirEvent) {
  auto state_tracker_ref =
      SystemStateTracker::create(getMockedProcessContextFactory());

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "chdir";
  bpf_event.header.process_id = 2;

  auto succeeded =
      BPFEventPublisher::processChdirEvent(state_tracker, bpf_event);

  EXPECT_FALSE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Now try again with the parameter but set the exit_code so that
  // the syscall fails
  bpf_event.header.exit_code = static_cast<std::uint64_t>(-1);

  // clang-format off
  bpf_event.out_field_map.insert(
    {
      "filename",

      {
        "filename",
        true,
        "/root"
      }
    }
  );
  // clang-format on

  succeeded = BPFEventPublisher::processChdirEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // The cwd should not have been changed yet
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).cwd,
            "/home/alessandro");

  // Finally, set the exit code correctly and try again
  bpf_event.header.exit_code = 0ULL;

  succeeded = BPFEventPublisher::processChdirEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // The cwd should now be /root
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).cwd, "/root");
}

TEST_F(BPFEventPublisherTests, processFchdirEvent) {
  auto state_tracker_ref =
      SystemStateTracker::create(getMockedProcessContextFactory());

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "fchdir";
  bpf_event.header.process_id = 2;

  auto succeeded =
      BPFEventPublisher::processFchdirEvent(state_tracker, bpf_event);

  EXPECT_FALSE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Now try again with the parameter but set the exit_code so that
  // the syscall fails
  bpf_event.header.exit_code = static_cast<std::uint64_t>(-1);

  // clang-format off
  bpf_event.in_field_map.insert(
    {
      "fd",

      {
        "fd",
        true,
        15ULL
      }
    }
  );
  // clang-format on

  succeeded = BPFEventPublisher::processFchdirEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // The cwd should not have been changed yet
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).cwd,
            "/home/alessandro");

  // Finally, set the exit code correctly and try again
  bpf_event.header.exit_code = 0ULL;

  succeeded = BPFEventPublisher::processFchdirEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // The cwd should now be the same path set in the file descriptor
  // 15
  auto state_tracker_context = state_tracker.getContextCopy();

  EXPECT_TRUE(validateFileDescriptor(state_tracker_context.process_map,
                                     2,
                                     15,
                                     false,
                                     "/usr/share/zsh/functions/Misc.zwc"));
}

TEST_F(BPFEventPublisherTests, processSocketEvent) {
  auto state_tracker_ref =
      SystemStateTracker::create(getMockedProcessContextFactory());

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "socket";
  bpf_event.header.process_id = 2;

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field family_field = {
    "family",
    true,
    0ULL
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field type_field = {
    "type",
    true,
    0ULL
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field protocol_field = {
    "protocol",
    true,
    0ULL
  };
  // clang-format on

  for (std::size_t i = 0U; i < 7; ++i) {
    bpf_event.in_field_map = {};

    if ((i & 1) != 0) {
      bpf_event.in_field_map.insert({family_field.name, family_field});
    }

    if ((i & 2) != 0) {
      bpf_event.in_field_map.insert({type_field.name, type_field});
    }

    if ((i & 4) != 0) {
      bpf_event.in_field_map.insert({protocol_field.name, protocol_field});
    }

    auto succeeded =
        BPFEventPublisher::processSocketEvent(state_tracker, bpf_event);

    EXPECT_FALSE(succeeded);
    EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);
  }

  // Now try again with all parameters but set the exit_code so that
  // the syscall fails. This event should be ignored and the operation
  // should succeed
  bpf_event.header.exit_code = static_cast<std::uint64_t>(-1);
  bpf_event.in_field_map.insert({family_field.name, family_field});
  bpf_event.in_field_map.insert({type_field.name, type_field});
  bpf_event.in_field_map.insert({protocol_field.name, protocol_field});

  auto succeeded =
      BPFEventPublisher::processSocketEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should still have only 8 file descriptors
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 8U);

  // Finally, set the exit code correctly and try again
  bpf_event.header.exit_code = 16ULL;
  succeeded = BPFEventPublisher::processSocketEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should now have a new file descriptor in the process context
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 9U);
}

TEST_F(BPFEventPublisherTests, processFcntlEvent) {
  auto state_tracker_ref =
      SystemStateTracker::create(getMockedProcessContextFactory());

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "fcntl";
  bpf_event.header.process_id = 2;

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field cmd_field = {
    "cmd",
    true,
    static_cast<std::uint64_t>(F_DUPFD)
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field fd_field = {
    "fd",
    true,
    15ULL
  };
  // clang-format on

  for (std::size_t i = 0U; i < 3; ++i) {
    bpf_event.in_field_map = {};

    if ((i & 1) != 0) {
      bpf_event.in_field_map.insert({cmd_field.name, cmd_field});
    }

    if ((i & 2) != 0) {
      bpf_event.in_field_map.insert({fd_field.name, fd_field});
    }

    auto succeeded =
        BPFEventPublisher::processFcntlEvent(state_tracker, bpf_event);

    EXPECT_FALSE(succeeded);
    EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);
  }

  // Now try again with all parameters but set the exit_code so that
  // the syscall fails
  bpf_event.header.exit_code = static_cast<std::uint64_t>(-1);

  bpf_event.in_field_map.insert({cmd_field.name, cmd_field});
  bpf_event.in_field_map.insert({fd_field.name, fd_field});

  auto succeeded =
      BPFEventPublisher::processFcntlEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should still have only 8 file descriptors
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 8U);

  // Finally, set the exit code correctly and try again
  bpf_event.header.exit_code = 16ULL;

  succeeded = BPFEventPublisher::processFcntlEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // We should now have a new file descriptor in the process context
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 9U);

  // Try once more, with a command that we ignore. This should have no effect
  // and the operation should succeed
  bpf_event.in_field_map["cmd"].data_var = static_cast<std::uint64_t>(F_GETFD);
  bpf_event.header.exit_code = 17ULL;

  succeeded = BPFEventPublisher::processFcntlEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 9U);
}

TEST_F(BPFEventPublisherTests, processConnectEvent) {
  auto state_tracker_ref =
      SystemStateTracker::create(getMockedProcessContextFactory());

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "connect";
  bpf_event.header.process_id = 2;

  // This will be read as AF_UNIX since it's all zeroed
  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field uservaddr_field = {
    "uservaddr",
    true,
    std::vector<std::uint8_t>(sizeof(sockaddr_un), 0)
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field fd_field = {
    "fd",
    true,
    15ULL
  };
  // clang-format on

  for (std::size_t i = 0U; i < 3; ++i) {
    bpf_event.in_field_map = {};

    if ((i & 1) != 0) {
      bpf_event.in_field_map.insert({uservaddr_field.name, uservaddr_field});
    }

    if ((i & 2) != 0) {
      bpf_event.in_field_map.insert({fd_field.name, fd_field});
    }

    auto succeeded =
        BPFEventPublisher::processConnectEvent(state_tracker, bpf_event);

    EXPECT_FALSE(succeeded);
    EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);
  }

  // Now try again with all parameters
  bpf_event.in_field_map.insert({uservaddr_field.name, uservaddr_field});
  bpf_event.in_field_map.insert({fd_field.name, fd_field});

  auto succeeded =
      BPFEventPublisher::processConnectEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);

  // Try again, with an invalid file descriptor; this will still work because
  // the state tracker will update the fd_map on the fly and emit the connect()
  // event anyway even if some data is missing
  bpf_event.in_field_map["fd"].data_var = 9999ULL;

  succeeded = BPFEventPublisher::processConnectEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);

  // Try again, with a broken sockaddr structure. This should return an error
  bpf_event.in_field_map["uservaddr"].data_var =
      std::vector<std::uint8_t>(1, 1);

  succeeded = BPFEventPublisher::processConnectEvent(state_tracker, bpf_event);
  EXPECT_FALSE(succeeded);
}

TEST_F(BPFEventPublisherTests, processAcceptEvent) {
  auto state_tracker_ref =
      SystemStateTracker::create(getMockedProcessContextFactory());

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "accept";
  bpf_event.header.process_id = 2;

  // This will be read as AF_UNIX since it's all zeroed
  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field upeer_sockaddr_field = {
    "upeer_sockaddr",
    true,
    std::vector<std::uint8_t>(sizeof(sockaddr_un), 0)
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field fd_field = {
    "fd",
    true,
    15ULL
  };
  // clang-format on

  for (std::size_t i = 0U; i < 3; ++i) {
    bpf_event.in_field_map = {};
    bpf_event.out_field_map = {};

    if ((i & 1) != 0) {
      bpf_event.out_field_map.insert(
          {upeer_sockaddr_field.name, upeer_sockaddr_field});
    }

    if ((i & 2) != 0) {
      bpf_event.in_field_map.insert({fd_field.name, fd_field});
    }

    auto succeeded =
        BPFEventPublisher::processAcceptEvent(state_tracker, bpf_event);

    EXPECT_FALSE(succeeded);
    EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);
  }

  // Now try again with all parameters but set the exit code so that
  // the syscall fails. This event should be ignored
  bpf_event.header.exit_code = static_cast<std::uint64_t>(-1);

  bpf_event.out_field_map.insert(
      {upeer_sockaddr_field.name, upeer_sockaddr_field});
  bpf_event.in_field_map.insert({fd_field.name, fd_field});

  auto succeeded =
      BPFEventPublisher::processAcceptEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 8U);

  // Try again, setting the correct exit code
  bpf_event.header.exit_code = 99ULL;
  succeeded = BPFEventPublisher::processAcceptEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 9U);

  // Try again, with a broken sockaddr structure. This event will be ignored
  // and this should always succeeds
  bpf_event.header.exit_code = 100ULL;
  bpf_event.out_field_map["upeer_sockaddr"].data_var =
      std::vector<std::uint8_t>(1, 1);

  succeeded = BPFEventPublisher::processAcceptEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 9U);
}

TEST_F(BPFEventPublisherTests, processAccept4Event) {
  auto state_tracker_ref =
      SystemStateTracker::create(getMockedProcessContextFactory());

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "accept4";
  bpf_event.header.process_id = 2;

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field flags_field = {
    "flags",
    true,
    0ULL
  };
  // clang-format on

  // This will be read as AF_UNIX since it's all zeroed
  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field upeer_sockaddr_field = {
    "upeer_sockaddr",
    true,
    std::vector<std::uint8_t>(sizeof(sockaddr_un), 0)
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field fd_field = {
    "fd",
    true,
    15ULL
  };
  // clang-format on

  for (std::size_t i = 0U; i < 7; ++i) {
    bpf_event.in_field_map = {};
    bpf_event.out_field_map = {};

    if ((i & 1) != 0) {
      bpf_event.out_field_map.insert(
          {upeer_sockaddr_field.name, upeer_sockaddr_field});
    }

    if ((i & 2) != 0) {
      bpf_event.in_field_map.insert({fd_field.name, fd_field});
    }

    if ((i & 4) != 0) {
      bpf_event.in_field_map.insert({flags_field.name, flags_field});
    }

    auto succeeded =
        BPFEventPublisher::processAccept4Event(state_tracker, bpf_event);

    EXPECT_FALSE(succeeded);
    EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);
  }

  // Now try again with all parameters but set the exit code so that
  // the syscall fails. This event should be ignored
  bpf_event.header.exit_code = static_cast<std::uint64_t>(-1);

  bpf_event.out_field_map.insert(
      {upeer_sockaddr_field.name, upeer_sockaddr_field});

  bpf_event.in_field_map.insert({fd_field.name, fd_field});
  bpf_event.in_field_map.insert({flags_field.name, flags_field});

  auto succeeded =
      BPFEventPublisher::processAccept4Event(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 8U);

  // Try again, setting the correct exit code
  bpf_event.header.exit_code = 99ULL;
  succeeded = BPFEventPublisher::processAccept4Event(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 9U);

  // Try again, with a broken sockaddr structure. This event will be ignored and
  // should always return as the operation has succeeded
  bpf_event.header.exit_code = 100ULL;
  bpf_event.out_field_map["upeer_sockaddr"].data_var =
      std::vector<std::uint8_t>(1, 1);

  succeeded = BPFEventPublisher::processAccept4Event(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 9U);
}

TEST_F(BPFEventPublisherTests, processBindEvent) {
  auto state_tracker_ref =
      SystemStateTracker::create(getMockedProcessContextFactory());

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass all parameters
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "bind";
  bpf_event.header.process_id = 2;

  // This will be read as AF_UNIX since it's all zeroed
  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field umyaddr_field = {
    "umyaddr",
    true,
    std::vector<std::uint8_t>(sizeof(sockaddr_un), 0)
  };
  // clang-format on

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field fd_field = {
    "fd",
    true,
    15ULL
  };
  // clang-format on

  for (std::size_t i = 0U; i < 3; ++i) {
    bpf_event.in_field_map = {};

    if ((i & 1) != 0) {
      bpf_event.in_field_map.insert({umyaddr_field.name, umyaddr_field});
    }

    if ((i & 2) != 0) {
      bpf_event.in_field_map.insert({fd_field.name, fd_field});
    }

    auto succeeded =
        BPFEventPublisher::processBindEvent(state_tracker, bpf_event);

    EXPECT_FALSE(succeeded);
    EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);
  }

  // Now try again with all parameters but set the exit code so that
  // the syscall fails. This event should be ignored
  bpf_event.header.exit_code = static_cast<std::uint64_t>(-1);
  bpf_event.in_field_map.insert({umyaddr_field.name, umyaddr_field});
  bpf_event.in_field_map.insert({fd_field.name, fd_field});

  auto succeeded =
      BPFEventPublisher::processBindEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 8U);

  // Try again, setting the correct exit code
  bpf_event.header.exit_code = 0ULL;
  succeeded = BPFEventPublisher::processBindEvent(state_tracker, bpf_event);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 8U);

  // Try again, with a broken sockaddr structure. We should get an error back
  bpf_event.in_field_map["umyaddr"].data_var = std::vector<std::uint8_t>(1, 1);

  succeeded = BPFEventPublisher::processBindEvent(state_tracker, bpf_event);

  EXPECT_FALSE(succeeded);
  EXPECT_EQ(state_tracker.getContextCopy().process_map.at(2).fd_map.size(), 8U);
}

TEST_F(BPFEventPublisherTests, processListenEvent) {
  auto state_tracker_ref =
      SystemStateTracker::create(getMockedProcessContextFactory());

  auto& state_tracker =
      static_cast<SystemStateTracker&>(*state_tracker_ref.get());

  EXPECT_EQ(state_tracker.getContextCopy().process_map.size(), 1U);

  // Processing should fail until we pass the file descriptor
  auto bpf_event = kBaseBPFEvent;
  bpf_event.name = "listen";
  bpf_event.header.process_id = 2;

  // clang-format off
  tob::ebpfpub::IFunctionTracer::Event::Field fd_field = {
    "fd",
    true,
    15ULL
  };
  // clang-format on

  auto succeeded =
      BPFEventPublisher::processListenEvent(state_tracker, bpf_event);

  EXPECT_FALSE(succeeded);

  // Now try again with all parameters but set the exit code so that
  // the syscall fails. This event should be ignored
  bpf_event.header.exit_code = static_cast<std::uint64_t>(-1);
  bpf_event.in_field_map.insert({fd_field.name, fd_field});

  succeeded = BPFEventPublisher::processListenEvent(state_tracker, bpf_event);
  EXPECT_TRUE(succeeded);

  // Try again, with the correct exit code
  bpf_event.header.exit_code = 0ULL;
  succeeded = BPFEventPublisher::processListenEvent(state_tracker, bpf_event);
  EXPECT_TRUE(succeeded);
}

} // namespace osquery
