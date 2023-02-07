/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/events/windows/etw/etw_publisher.h>

namespace osquery {

EtwPublisherBase::EtwPublisherBase(const std::string& name) {
  name_ = name;
}

EtwController& EtwPublisherBase::EtwEngine() {
  return etwController_;
}

Status EtwPublisherBase::run() {
  return Status::failure(0,
                         "ETW provider is driven by event callbacks. "
                         "A pooling thread is not required.");
}

std::function<void(const EtwEventDataRef&)>
EtwPublisherBase::getPostProcessorCallback() {
  return [this](const EtwEventDataRef& data) {
    this->providerPostProcessor(data);
  };
}

} // namespace osquery
