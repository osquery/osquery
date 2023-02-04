/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <future>
#include <memory>
#include <optional>
#include <set>

#include <osquery/logger/logger.h>

#include "osquery/events/containerd/events.pb.h"

namespace osquery {
class IBaseRequestOutput {
 public:
  virtual ~IBaseRequestOutput(void) = default;

  virtual bool running() const = 0;
  virtual void terminate() = 0;

  virtual std::future<Status>& status() = 0;

  virtual bool ready() const = 0;
};

template <typename DataType>
class IBaseStreamRequestOutput : public IBaseRequestOutput {
 public:
  virtual ~IBaseStreamRequestOutput() = default;

  virtual std::vector<DataType> getData() = 0;
};

template <typename DataType>
class IBaseItemRequestOutput : public IBaseRequestOutput {
 public:
  virtual ~IBaseItemRequestOutput() = default;

  virtual DataType getData() = 0;
};

using IQueryEventRequestOutput =
    IBaseStreamRequestOutput<containerd::services::events::v1::Envelope>;

using IQueryEventRequestOutputRef = std::shared_ptr<IQueryEventRequestOutput>;

class IAsyncAPIClient {
 public:
  virtual ~IAsyncAPIClient() = default;

  virtual IQueryEventRequestOutputRef subscribeEvents(
      const containerd::services::events::v1::SubscribeRequest&
          subscribe_request) const = 0;
};

using IAsyncAPIClientRef = std::shared_ptr<IAsyncAPIClient>;

Status createAsyncAPIClient(IAsyncAPIClientRef& obj,
                            const std::string& address);
} // namespace osquery
