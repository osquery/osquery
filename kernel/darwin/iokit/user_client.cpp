/*
 *  Copyright (c) 2015, Google, Inc.
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "kernel/darwin/iokit/user_client.h"

#include <sys/proc.h>

#include "kernel/darwin/iokit/public.h"
#include "kernel/darwin/iokit/logging.h"

#define super IOUserClient

// The define above can't be used in this function, must use the full name.
OSDefineMetaClassAndStructors(com_facebook_iokit_osqueryUserClient,
                              IOUserClient);

# pragma mark Driver Management

bool OsqueryUserClientClassName::initWithTask(
    task_t owningTask, void *securityID, UInt32 type) {
  if (clientHasPrivilege(owningTask, kIOClientPrivilegeAdministrator)
      != KERN_SUCCESS) {
    LOGW("Unprivileged client attempted to connect.");
    return false;
  }
  if (!super::initWithTask(owningTask, securityID, type)) {
    return false;
  }
  return true;
}

bool OsqueryUserClientClassName::start(IOService *provider) {
  // Verify that this user client is being started with a provider that it knows
  // how to communicate with.
  provider_ = OSDynamicCast(com_facebook_iokit_osquery, provider);
  if (provider_ == nullptr) {
    return false;
  }
  if (!provider_->open(this)) {
    LOGW("A second client tried to connect.");
    return false;
  }
  if (!super::start(provider)) {
    return false;
  }
  return true;
}

IOReturn OsqueryUserClientClassName::clientClose() {
  LOGD("Closing client.");
  // If we have one and we are the one who opened it, close provider.
  if (provider_ && provider_->isOpen(this)) {
    provider_->close(this);
  }
  terminate();
  return kIOReturnSuccess;
}

bool OsqueryUserClientClassName::didTerminate(
    IOService *provider, IOOptionBits options, bool *defer) {
  LOGD("User client terminating.");
  // If we have one and we are the one who opened it, close provider.
  if (provider_ && provider_->isOpen(this)) {
    provider_->close(this);
  }
  *defer = false;
  return super::didTerminate(provider, options, defer);
}

IOReturn OsqueryUserClientClassName::registerNotificationPort(
    mach_port_t port, UInt32 type, UInt32 ref) {
  return provider_->SetNotificationPort(port);
}

IOReturn OsqueryUserClientClassName::clientMemoryForType(
    UInt32 type, IOOptionBits *options, IOMemoryDescriptor **memory) {
  *memory = nullptr;
  *options = 0;
  if (type != kIODefaultMemoryType) {
    return kIOReturnNoMemory;
  }
  // You don't need to balance with a release() because the user client does
  // the release() for you.
  IOMemoryDescriptor *memory_to_share = provider_->GetSharedMemory();
  if (memory_to_share) {
    memory_to_share->retain();
    *memory = memory_to_share;
  }
  return kIOReturnSuccess;
}

#undef super
