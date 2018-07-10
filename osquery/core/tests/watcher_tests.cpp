/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/tables.h>

#include "osquery/core/watcher.h"
#include "osquery/tests/test_util.h"

using namespace testing;

namespace osquery {

DECLARE_uint64(watchdog_delay);

class WatcherTests : public testing::Test {};

/**
 * @brief Begin with a mock watcher runner.
 *
 * The Watcher class implements a small static state.
 *
 * The WatcherRunner class implements the state machine of a watchdog process
 * as a Runnable, in a dedicated thread. We begin testing by exercising parts
 * of that state machine.
 */
class MockWatcherRunner : public WatcherRunner {
 public:
  MockWatcherRunner(int argc, char** argv, bool use_worker)
      : WatcherRunner(argc, argv, use_worker) {}

  /// The state machine requested the 'worker' to stop.
  MOCK_CONST_METHOD1(stopChild, void(const PlatformProcess& child));

  /// The state machine is inspecting the 'worker' health and performance.
  MOCK_CONST_METHOD1(isChildSane, Status(const PlatformProcess& child));

 private:
  FRIEND_TEST(WatcherTests, test_watcher);
};

/**
 * @brief A scoped implementation of a cross-platform process.
 *
 * During the WorkerRunner exercises an external cross-platform process
 * representation is provided. To better control the WorkerRunner state machine
 * we will manipulate operating system abstractions to control process state.
 */
class FakePlatformProcess : public PlatformProcess {
 public:
  /// Simplified ctor set for our use cases.
  FakePlatformProcess(PlatformPidType id) : PlatformProcess(id) {}

  ProcessState checkStatus(int& _status) const {
    _status = status_;
    return state_;
  }

 private:
  /// Allow our friend test classes to emulate the operating system's PoV.
  void setStatus(ProcessState state, int status) {
    state_ = state;
    status_ = status;
  }

 private:
  ProcessState state_{PROCESS_STILL_ALIVE};
  int status_{0};

 private:
  FRIEND_TEST(WatcherTests, test_watcherrunner_watch);
  FRIEND_TEST(WatcherTests, test_watcherrunner_stop);
  FRIEND_TEST(WatcherTests, test_watcherrunner_unhealthy_delay);
};

TEST_F(WatcherTests, test_watcherrunner_watch) {
  MockWatcherRunner runner(0, nullptr, false);

  // Use the cross-platform abstractions to inspect the current test process.
  auto test_process = PlatformProcess::getCurrentProcess();
  // Initialize a scoped (fake) process abstraction.
  auto fake_test_process = FakePlatformProcess(test_process->nativeHandle());

  // The ::watch method is a single iteration of worker health checking.
  // Unless the watcher has entered a shutdown phase, every iteration should
  // check the worker sanity.
  EXPECT_CALL(runner, isChildSane(_)).WillOnce(Return(Status(0)));

  // The above expectation returns a sane child state.
  // This ::watch iteration should NOT attempt to stop the worker.
  EXPECT_CALL(runner, stopChild(_)).Times(0);

  // When triggering a watch, set the assumed process status.
  fake_test_process.setStatus(PROCESS_STILL_ALIVE, 0);

  // Trigger our expectations.
  EXPECT_TRUE(runner.watch(fake_test_process));
}

TEST_F(WatcherTests, test_watcherrunner_stop) {
  MockWatcherRunner runner(0, nullptr, false);

  auto test_process = PlatformProcess::getCurrentProcess();
  auto fake_test_process = FakePlatformProcess(test_process->nativeHandle());

  EXPECT_CALL(runner, isChildSane(_)).Times(0);
  EXPECT_CALL(runner, stopChild(_)).Times(0);

  // Now set the process status to an error state.
  fake_test_process.setStatus(PROCESS_ERROR, 0);

  // Trigger our expectations, the watch method will now return false.
  EXPECT_FALSE(runner.watch(fake_test_process));
}

class MockWithWatchWatcherRunner : public WatcherRunner {
 public:
  MockWithWatchWatcherRunner(int argc, char** argv, bool use_worker)
      : WatcherRunner(argc, argv, use_worker) {}

  /// This super-mock now mocks the watch method.
  MOCK_CONST_METHOD1(watch, bool(const PlatformProcess& child));

  MOCK_CONST_METHOD2(isWatcherHealthy,
                     Status(const PlatformProcess& watcher,
                            PerformanceState& watcher_state));

  /// The state machine is starting, and is forking a managed extension.
  MOCK_METHOD1(createExtension, void(const std::string& extension));

  /// The state machine is starting, and is forking the managed 'worker'.
  MOCK_METHOD0(createWorker, void());
};

TEST_F(WatcherTests, test_watcherrunner_loop) {
  // This time construct the runner with a use_worker=true.
  MockWithWatchWatcherRunner runner(0, nullptr, true);

  // Use a method introduced for testing purposes to request a single run of
  // the WatcherRunner's thread entry point.
  runner.runOnce();

  // Watch will be called once, for the worker only, since there are no
  // extensions configured.
  EXPECT_CALL(runner, watch(_)).WillOnce(Return(true));
  // Since the watch method is configured to return true, no worker is created.
  EXPECT_CALL(runner, createWorker()).Times(0);
  // The single-loop must check if itself is healthy.
  EXPECT_CALL(runner, isWatcherHealthy(_, _)).WillOnce(Return(Status(0)));

  runner.start();
}

TEST_F(WatcherTests, test_watcherrunner_loop_failure) {
  MockWithWatchWatcherRunner runner(0, nullptr, true);
  runner.runOnce();

  // Now the watch method returns false, indicating the previous worker failed
  // performance checked and was stopped.
  EXPECT_CALL(runner, watch(_)).WillOnce(Return(false));
  // Since the watch failed, the thread should spawn another worker.
  EXPECT_CALL(runner, createWorker()).Times(1);
  EXPECT_CALL(runner, isWatcherHealthy(_, _)).WillOnce(Return(Status(0)));

  runner.start();
}

TEST_F(WatcherTests, test_watcherrunner_loop_disabled) {
  // Now construct without using a worker.
  MockWithWatchWatcherRunner runner(0, nullptr, false);
  runner.runOnce();

  // There is no worker process, nothing should be watched.
  EXPECT_CALL(runner, watch(_)).Times(0);
  // Without a worker process, the watcher does not watch itself.
  EXPECT_CALL(runner, isWatcherHealthy(_, _)).Times(0);

  runner.start();
}

class FakeWatcherRunner : public WatcherRunner {
 public:
  FakeWatcherRunner(int argc, char** argv, bool use_worker)
      : WatcherRunner(argc, argv, use_worker) {}

  /**
   * @brief What the runner's internals will use as process state.
   *
   * Internal calls to getProcessRow will return this structure.
   */
  void setProcessRow(QueryData qd) {
    qd_ = std::move(qd);
  }

  /// The tests do not have access to the processes table.
  QueryData getProcessRow(pid_t pid) const {
    return qd_;
  }

 private:
  /// If a worker/extension has otherwise gone insane, stop it.
  void stopChild(const PlatformProcess& child) const {}

 private:
  QueryData qd_;
};

TEST_F(WatcherTests, test_watcherrunner_watcherhealth) {
  FakeWatcherRunner runner(0, nullptr, true);

  // Construct a process state, assume this would have been returned from the
  // processes table, which the WorkerRunner normally uses internally.
  Row r;
  r["parent"] = INTEGER(1);
  r["user_time"] = INTEGER(100);
  r["system_time"] = INTEGER(100);
  r["resident_size"] = INTEGER(100);
  runner.setProcessRow({r});

  // Hold the process and process state externally.
  // Normally the WatcherRunner's entry point will persist these and use them
  // as input to the next testable method to compare changes.
  auto test_process = PlatformProcess::getCurrentProcess();
  PerformanceState state;
  // The inputs are sane.
  EXPECT_TRUE(runner.isWatcherHealthy(*test_process, state));
  // Calling the method again should internally detect no change, this means
  // the state is still normal.
  EXPECT_TRUE(runner.isWatcherHealthy(*test_process, state));

  // The state should track the initial memory value.
  EXPECT_EQ(100U, state.initial_footprint);

  // The measurement of latency applies an interval value normalization.
  EXPECT_EQ(100U, state.user_time);
  EXPECT_EQ(0U, state.sustained_latency);

  // Now we can alter the performance.
  // Let us emulate the watcher having just allocated 1G of memory.
  r["resident_size"] = INTEGER(1024 * 1024 * 1024);
  runner.setProcessRow({r});

  auto status = runner.isWatcherHealthy(*test_process, state);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(status.getMessage(), "Memory limits exceeded");

  // Now emulate a rapid increase in CPU requirements.
  r["user_time"] = INTEGER(1024 * 1024 * 1024);
  runner.setProcessRow({r});
  runner.isWatcherHealthy(*test_process, state);
  EXPECT_EQ(1U, state.sustained_latency);

  // And again, the CPU continues to increase from the system perspective.
  r["system_time"] = INTEGER(1024 * 1024 * 1024);
  runner.setProcessRow({r});
  runner.isWatcherHealthy(*test_process, state);
  EXPECT_EQ(2U, state.sustained_latency);
}

TEST_F(WatcherTests, test_watcherrunner_unhealthy_delay) {
  FakeWatcherRunner runner(0, nullptr, true);

  auto test_process = PlatformProcess::getCurrentProcess();
  auto fake_test_process = FakePlatformProcess(test_process->nativeHandle());
  fake_test_process.setStatus(PROCESS_STILL_ALIVE, 0);

  // Set up a fake test process and place it into an healthy state.
  Row r;
  r["parent"] = isPlatform(PlatformType::TYPE_WINDOWS)
                    ? INTEGER(test_process->pid())
                    : INTEGER(test_process->nativeHandle());
  r["user_time"] = INTEGER(100);
  r["system_time"] = INTEGER(100);
  r["resident_size"] = INTEGER(100);
  runner.setProcessRow({r});

  // Check the fake process sanity, which records the state at t=0.
  EXPECT_TRUE(runner.isChildSane(fake_test_process));

  // Update the fake process resident memory, make it unhealthy.
  r["resident_size"] = INTEGER(1024 * 1024 * 1024);
  runner.setProcessRow({r});

  // Set the watchdog to delay 1000s.
  auto delay = FLAGS_watchdog_delay;
  FLAGS_watchdog_delay = 1000;
  // Trigger our expectations, the watch method will return true.
  // This will NOT call stopChild as the delay has not passed.
  EXPECT_TRUE(runner.watch(fake_test_process));

  // Now set the watchdog to no delay.
  FLAGS_watchdog_delay = 0;
  // This will call stopChild as there is no delay and the child is unhealthy.
  EXPECT_FALSE(runner.watch(fake_test_process));

  FLAGS_watchdog_delay = delay;
}
} // namespace osquery
