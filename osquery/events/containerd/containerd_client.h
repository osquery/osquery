/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/core/flags.h>
#include <osquery/logger/logger.h>

#include "client_interface.h"

namespace osquery {

class ContainerdAsyncAPIClient final : public IAsyncAPIClient {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  ContainerdAsyncAPIClient(const std::string& address);

 public:
  ~ContainerdAsyncAPIClient();

  IQueryEventRequestOutputRef subscribeEvents(
      const containerd::services::events::v1::SubscribeRequest&
          subscribe_request) const override;
  Status runEventLoop(IQueryEventRequestOutputRef output);

  ContainerdAsyncAPIClient(const ContainerdAsyncAPIClient&) = delete;
  ContainerdAsyncAPIClient& operator=(const ContainerdAsyncAPIClient&) = delete;

  friend Status createAsyncAPIClient(IAsyncAPIClientRef& obj,
                                     const std::string& address);
};
} // namespace osquery
