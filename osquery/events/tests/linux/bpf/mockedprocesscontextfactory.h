/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/events/linux/bpf/iprocesscontextfactory.h>

namespace osquery {

class MockedProcessContextFactory final : public IProcessContextFactory {
 public:
  MockedProcessContextFactory() = default;
  virtual ~MockedProcessContextFactory() override = default;

  std::size_t invocationCount() const;
  void failNextRequest();

  virtual bool captureSingleProcess(ProcessContext& process_context,
                                    pid_t process_id) const override;

  virtual bool captureAllProcesses(
      ProcessContextMap& process_map) const override;

 private:
  mutable bool fail_next_request{false};
  mutable std::size_t invocation_count{false};
};

} // namespace osquery
