/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/events/windows/etw/etw_test_session_lock.h>
#include <osquery/logger/logger.h>

namespace osquery {

Status EtwTestSessionLock::acquire(std::unique_ptr<EtwTestSessionLock>& lock) {
  auto handle = CreateMutexW(nullptr, FALSE, L"Global\\OsqueryETWTestSessions");
  if (handle == nullptr) {
    auto status = Status::failure("Cannot create ETW test mutex: " +
                                  std::to_string(GetLastError()));
    LOG(ERROR) << status.getMessage();
    return status;
  }

  LOG(INFO) << "Waiting for exclusive access to ETW test sessions";
  auto wait_result = WaitForSingleObject(handle, 300000);
  if (wait_result != WAIT_OBJECT_0 && wait_result != WAIT_ABANDONED) {
    auto error = wait_result == WAIT_TIMEOUT
                     ? "Timed out waiting for ETW test mutex"
                     : "Cannot acquire ETW test mutex: " +
                           std::to_string(GetLastError());
    if (!CloseHandle(handle)) {
      LOG(ERROR) << "Cannot close ETW test mutex: " << GetLastError();
    }
    LOG(ERROR) << error;
    return Status::failure(error);
  }

  if (wait_result == WAIT_ABANDONED) {
    LOG(WARNING) << "Previous ETW test mutex owner exited without releasing "
                    "it; reclaiming trace sessions";
  }
  lock.reset(new EtwTestSessionLock(handle));
  return Status::success();
}

EtwTestSessionLock::~EtwTestSessionLock() {
  if (!ReleaseMutex(handle_)) {
    LOG(ERROR) << "Cannot release ETW test mutex: " << GetLastError();
  }
  if (!CloseHandle(handle_)) {
    LOG(ERROR) << "Cannot close ETW test mutex: " << GetLastError();
  }
}

} // namespace osquery
