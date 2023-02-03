/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/events/windows/etw/etw_controller.h>
#include <osquery/events/windows/etw/etw_kernel_session.h>
#include <osquery/events/windows/etw/etw_post_processing_pipeline.h>
#include <osquery/events/windows/etw/etw_provider_config.h>
#include <osquery/events/windows/etw/etw_user_session.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/status/status.h>

namespace osquery {

// Returns a reference to the single global EtwController instance
EtwController& EtwController::instance() {
  static EtwController instance;
  return instance;
}

//  New events get stored in the post-processing queue
void EtwController::dispatchETWEvents(const EtwEventDataRef& data) {
  // storing the event in the thread-safe concurrent event queue
  if (concurrentQueue_) {
    concurrentQueue_->push(data);
  }
}

Status EtwController::addProvider(const EtwProviderConfig& configData) {
  // Thread-safe safeguard - multiple callers might be trying to add a provider
  std::lock_guard<std::mutex> lock(mutex_);

  // Sanity check on input ETW provider configuration data
  Status validProvider = configData.isValid();
  if (!validProvider.ok()) {
    return Status::failure("Invalid ETW provider data: " +
                           validProvider.getMessage());
  }

  // Initialize ETW controller if needed
  Status initStatus = initialize();
  if (!initStatus.ok()) {
    return Status::failure(initStatus.getMessage());
  }

  // Adding post-processors callbacks to handle
  Status postProcessingStatus =
      etwPostProcessingEngine_->addProvider(configData);

  if (!postProcessingStatus.ok()) {
    return Status::failure(postProcessingStatus.getMessage());
  }

  // ETW configuration data contains information to determine if an userspace or
  // kernelspace ETW provider is being requested.
  if (configData.isUserProvider()) {
    Status addUserProviderStatus = etwUserSession_->addProvider(configData);

    if (!addUserProviderStatus.ok()) {
      return Status::failure(addUserProviderStatus.getMessage());
    }

  } else {
    Status addKernelProviderStatus = etwKernelSession_->addProvider(configData);

    if (!addKernelProviderStatus.ok()) {
      return Status::failure(addKernelProviderStatus.getMessage());
    }
  }

  return Status::success();
}

// ETW trace sessions for userspace and kernelspace providers, along with
// post-processing pipeline is started here.
Status EtwController::startProcessing() {
  // sanity checks on processing engines
  if (!etwPostProcessingEngine_) {
    return Status::failure("ETW Post processing engine not ready");
  }

  if (!etwUserSession_) {
    return Status::failure("ETW User session processing engine not ready");
  }

  if (!etwKernelSession_) {
    return Status::failure("ETW Kernel session processing engine not ready");
  }

  // Spinning up runnable osquery services
  Status pipelineStatus = Dispatcher::addService(etwPostProcessingEngine_);
  if (!pipelineStatus.ok()) {
    return Status::failure("ETW Post processing engine couldn't be started: " +
                           pipelineStatus.getMessage());
  }

  Status userStatus = Dispatcher::addService(etwUserSession_);
  if (!userStatus.ok()) {
    return Status::failure("User ETW trace session couldn't be started: " +
                           userStatus.getMessage());
  }

  Status kernelStatus = Dispatcher::addService(etwKernelSession_);
  if (!kernelStatus.ok()) {
    return Status::failure("Kernel ETW trace session couldn't be started: " +
                           userStatus.getMessage());
  }

  return Status::success();
}

bool EtwController::isInitialized() const {
  return initialized_;
}

Status EtwController::initialize() {
  if (initialized_) {
    return Status::success();
  }

  // Initializing concurrent ETW event queue
  concurrentQueue_ = std::make_shared<ConcurrentEventQueue>();
  if (!concurrentQueue_) {
    return Status::failure("There was a problem allocating concurrent queue");
  }

  // Initializing ETW userspace trace session
  etwUserSession_ =
      std::make_shared<UserEtwSessionRunnable>(runNameUserETWSession);
  if (!etwUserSession_) {
    return Status::failure("There was a problem allocating ETW User Session");
  }

  // Initializing ETW kernelspace trace session
  etwKernelSession_ =
      std::make_shared<KernelEtwSessionRunnable>(runNameKernelETWSession);
  if (!etwKernelSession_) {
    return Status::failure("There was a problem allocating ETW Kernel Session");
  }

  // Initializing ETW post processing engine
  etwPostProcessingEngine_ = std::make_shared<EtwPostProcessorsRunnable>(
      runNamePostProcessingEngine, concurrentQueue_);
  if (!etwPostProcessingEngine_) {
    return Status::failure(
        "There was a problem allocating ETW Post Processing Engine");
  }

  // Launching processing threads
  auto processThreadStatus = startProcessing();
  if (!processThreadStatus.ok()) {
    return Status::failure(
        "There was a problem running ETW engine processing threads: " +
        processThreadStatus.getMessage());
  }

  initialized_ = true;

  return Status::success();
}

} // namespace osquery